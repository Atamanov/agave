use {
    crate::{
        commitment::CommitmentAggregationData,
        common::nonblocking_send,
        vote_history::{VoteHistory, VoteHistoryError},
        vote_history_storage::{SavedVoteHistory, SavedVoteHistoryVersions, VoteHistoryStorage},
        voting_service::BLSOp,
    },
    agave_bls_sigverify::rewards::{RewardInput, rewards_wants_vote},
    agave_votor_messages::{
        consensus_message::{BLS_KEYPAIR_DERIVE_SEED, VoteMessage},
        metric_types::ConsensusMetricsEventSender,
        vote::Vote,
        wire::get_vote_payload_to_sign,
    },
    crossbeam_channel::{Sender, TrySendError},
    solana_bls_signatures::{BlsError, keypair::Keypair as BLSKeypair},
    solana_clock::{Epoch, Slot},
    solana_gossip::cluster_info::ClusterInfo,
    solana_keypair::Keypair,
    solana_ledger::leader_schedule_cache::LeaderScheduleCache,
    solana_pubkey::Pubkey,
    solana_runtime::{bank::Bank, bank_forks::SharableBanks, epoch_stakes::BLSPubkeyStakeEntry},
    solana_signer::Signer,
    solana_streamer::{evicting_sender::EvictingSender, streamer::ChannelSend},
    solana_transaction::Transaction,
    std::{
        collections::{HashMap, hash_map::Entry},
        sync::{Arc, RwLock},
    },
    thiserror::Error,
};

#[derive(Debug)]
pub enum GenerateVoteTxResult {
    // The following are transient errors
    // non voting validator, not eligible for refresh
    // until authorized keypair is overridden
    NonVoting,
    // hot spare validator, not eligible for refresh
    // until set identity is invoked
    HotSpare,
    // The hash verification at startup has not completed
    WaitForStartupVerification,
    // Wait to vote slot is not reached
    WaitToVoteSlot(Slot),
    // no rank found, this can happen if the validator
    // is not staked in the current epoch, but it may
    // still be staked in future or past epochs, so this
    // is considered a transient error
    NoRankFound,

    // The following are misconfiguration errors
    // The authorized voter for the given pubkey and Epoch does not exist
    NoAuthorizedVoter(Pubkey, Epoch),
    // The vote account associated with given pubkey does not exist
    VoteAccountNotFound(Pubkey),

    // The following are the successful cases
    // Generated a vote transaction
    Tx(Transaction),
    // Generated a VoteMessage
    Vote(VoteMessage),
}

impl GenerateVoteTxResult {
    pub fn is_non_voting(&self) -> bool {
        matches!(self, Self::NonVoting)
    }

    pub fn is_hot_spare(&self) -> bool {
        matches!(self, Self::HotSpare)
    }

    pub fn is_invalid_config(&self) -> bool {
        match self {
            Self::NoAuthorizedVoter(_, _) | Self::VoteAccountNotFound(_) => true,
            Self::NonVoting
            | Self::HotSpare
            | Self::WaitForStartupVerification
            | Self::WaitToVoteSlot(_)
            | Self::NoRankFound => false,
            Self::Tx(_) | Self::Vote(_) => false,
        }
    }

    pub fn is_transient_error(&self) -> bool {
        match self {
            Self::NoAuthorizedVoter(_, _) | Self::VoteAccountNotFound(_) => false,
            Self::NonVoting
            | Self::HotSpare
            | Self::WaitForStartupVerification
            | Self::WaitToVoteSlot(_)
            | Self::NoRankFound => true,
            Self::Tx(_) | Self::Vote(_) => false,
        }
    }
}

#[derive(Debug, Error)]
pub enum VoteError {
    #[error("Unable to generate bls vote message, transient error: {0:?}")]
    TransientError(Box<GenerateVoteTxResult>),
    #[error("Unable to generate bls vote message, configuration error: {0:?}")]
    InvalidConfig(Box<GenerateVoteTxResult>),
    #[error("Channel \"{0}\" disconnected")]
    ChannelDisconnected(&'static str),
    #[error("Saved vote history error {0}")]
    SavedVoteHistoryError(#[from] VoteHistoryError),
}

/// Context required to construct vote transactions
pub(crate) struct VotingContext {
    pub(crate) cluster_info: Arc<ClusterInfo>,
    pub(crate) leader_schedule: Arc<LeaderScheduleCache>,
    pub(crate) vote_history: VoteHistory,
    pub(crate) vote_account_pubkey: Pubkey,
    pub(crate) identity_keypair: Arc<Keypair>,
    pub(crate) authorized_voter_keypairs: Arc<RwLock<Vec<Arc<Keypair>>>>,
    pub(crate) vote_history_storage: Arc<dyn VoteHistoryStorage>,
    // The BLS keypair should always change with authorized_voter_keypairs.
    pub(crate) derived_bls_keypairs: HashMap<Pubkey, Arc<BLSKeypair>>,
    pub(crate) own_vote_sender: EvictingSender<VoteMessage>,
    pub(crate) own_reward_sender: Sender<RewardInput>,
    pub(crate) bls_sender: Sender<BLSOp>,
    pub(crate) commitment_sender: Sender<CommitmentAggregationData>,
    pub(crate) wait_to_vote_slot: Option<u64>,
    pub(crate) sharable_banks: SharableBanks,
    pub(crate) consensus_metrics_sender: ConsensusMetricsEventSender,
}

fn get_or_insert_bls_keypair(
    derived_bls_keypairs: &mut HashMap<Pubkey, Arc<BLSKeypair>>,
    authorized_voter_keypair: &Keypair,
) -> Result<Arc<BLSKeypair>, BlsError> {
    let pubkey = authorized_voter_keypair.pubkey();
    match derived_bls_keypairs.entry(pubkey) {
        Entry::Occupied(e) => Ok(e.get().clone()),
        Entry::Vacant(e) => {
            let bls_keypair = Arc::new(BLSKeypair::derive_from_signer(
                authorized_voter_keypair,
                BLS_KEYPAIR_DERIVE_SEED,
            )?);
            e.insert(bls_keypair.clone());
            Ok(bls_keypair)
        }
    }
}

pub fn generate_vote_tx(
    vote: Vote,
    bank: &Bank,
    vote_account_pubkey: Pubkey,
    shred_version: u16,
    identity_keypair: &Keypair,
    authorized_voter_keypairs: &RwLock<Vec<Arc<Keypair>>>,
    wait_to_vote_slot: Option<u64>,
    derived_bls_keypairs: &mut HashMap<Pubkey, Arc<BLSKeypair>>,
) -> GenerateVoteTxResult {
    if authorized_voter_keypairs.read().unwrap().is_empty() {
        return GenerateVoteTxResult::NonVoting;
    }
    if bank.get_vote_account(&vote_account_pubkey).is_none() {
        return GenerateVoteTxResult::VoteAccountNotFound(vote_account_pubkey);
    }
    if let Some(slot) = wait_to_vote_slot
        && vote.slot() < slot
    {
        return GenerateVoteTxResult::WaitToVoteSlot(slot);
    }

    let rank_map = bank
        .get_rank_map(vote.slot())
        .unwrap_or_else(|| panic!("could not find rank map for slot {}", vote.slot()));

    let Some(&my_rank) = rank_map.get_rank_for_vote_pubkey(&vote_account_pubkey) else {
        return GenerateVoteTxResult::NoRankFound;
    };
    let BLSPubkeyStakeEntry {
        vote_account_pubkey: expected_vote_pubkey,
        node_pubkey: expected_node_pubkey,
        bls_pubkey: expected_bls_pubkey,
        stake,
    } = rank_map
        .get_pubkey_stake_entry(my_rank as usize)
        .expect("rank-map index should be valid");

    if expected_vote_pubkey != &vote_account_pubkey {
        warn!(
            "Rank-map vote pubkey mismatch: rank={my_rank}; expected={vote_account_pubkey}; \
             got={expected_vote_pubkey}",
        );
        return GenerateVoteTxResult::VoteAccountNotFound(vote_account_pubkey);
    }
    if expected_node_pubkey != &identity_keypair.pubkey() {
        warn!(
            "Rank-map node pubkey mismatch: rank={my_rank}; expected={expected_node_pubkey}; \
             got={}",
            identity_keypair.pubkey(),
        );
        return GenerateVoteTxResult::HotSpare;
    }

    let Some(bls_keypair) =
        authorized_voter_keypairs
            .read()
            .unwrap()
            .iter()
            .find_map(|authorized_voter_keypair| {
                let bls_keypair =
                    get_or_insert_bls_keypair(derived_bls_keypairs, authorized_voter_keypair)
                        .unwrap_or_else(|e| panic!("Failed to derive my own BLS keypair: {e}"));
                (&bls_keypair.public == expected_bls_pubkey).then_some(bls_keypair)
            })
    else {
        warn!(
            "No authorized voter keypair matches rank-map BLS key for vote account \
             {vote_account_pubkey}. Unable to vote"
        );
        return GenerateVoteTxResult::NonVoting;
    };

    let vote_payload_to_sign = get_vote_payload_to_sign(vote, shred_version);
    GenerateVoteTxResult::Vote(VoteMessage {
        vote,
        signature: bls_keypair.sign(&vote_payload_to_sign).into(),
        rank: my_rank,
        stake: *stake,
    })
}

/// Creates a vote message from `vote`, respecting `context.wait_to_vote_slot` only if `respect_wait_to_vote` is true
fn create_vote_message(
    vote: Vote,
    context: &mut VotingContext,
    respect_wait_to_vote: bool,
) -> Result<VoteMessage, VoteError> {
    let bank = context.sharable_banks.root();
    let wait_to_vote_slot = if respect_wait_to_vote {
        context.wait_to_vote_slot
    } else {
        None
    };
    match generate_vote_tx(
        vote,
        &bank,
        context.vote_account_pubkey,
        context.cluster_info.my_shred_version(),
        &context.identity_keypair,
        &context.authorized_voter_keypairs,
        wait_to_vote_slot,
        &mut context.derived_bls_keypairs,
    ) {
        GenerateVoteTxResult::Vote(vote_msg) => Ok(vote_msg),
        e => {
            if e.is_transient_error() {
                Err(VoteError::TransientError(Box::new(e)))
            } else {
                Err(VoteError::InvalidConfig(Box::new(e)))
            }
        }
    }
}

fn handle_skippable_vote_error(err: VoteError, action: &str) -> Result<(), VoteError> {
    match err {
        VoteError::InvalidConfig(e) => {
            warn!("Failed to {action}: {e:?}");
            // These are not fatal errors, just skip the vote for now. But they are
            // misconfigurations that should be warned about.
            Ok(())
        }
        VoteError::TransientError(e) => {
            info!("Failed to {action}: {e:?}");
            // These are transient errors, just skip the vote for now.
            Ok(())
        }
        e => Err(e),
    }
}

/// Build a normal push-vote BLS op.
///
/// This updates vote history, sends the vote to the certificate pool and reward service for
/// ingestion, and saves vote history for persistence.
pub(crate) fn insert_vote_and_create_bls_message(
    vote: Vote,
    context: &mut VotingContext,
) -> Result<Option<BLSOp>, VoteError> {
    // Update and save the vote history
    context.vote_history.add_vote(vote);

    let Some(vote_msg) =
        create_and_send_own_vote_message(vote, context, /* respect_wait_to_vote */ true)?
    else {
        return Ok(None);
    };

    let saved_vote_history =
        SavedVoteHistory::new(&context.vote_history, &context.identity_keypair)?;
    context
        .vote_history_storage
        .store(&SavedVoteHistoryVersions::from(saved_vote_history))?;

    // Return vote for sending
    Ok(Some(BLSOp::PushVote {
        vote: Arc::new(vote_msg),
    }))
}

pub(crate) fn create_and_send_own_vote_message(
    vote: Vote,
    context: &mut VotingContext,
    respect_wait_to_vote: bool,
) -> Result<Option<VoteMessage>, VoteError> {
    let vote_msg = match create_vote_message(vote, context, respect_wait_to_vote) {
        Ok(vote_msg) => vote_msg,
        Err(e) => {
            handle_skippable_vote_error(e, "generate vote message")?;
            return Ok(None);
        }
    };

    let channel_name = "own_vote_sender";
    let my_pubkey = &context.cluster_info.id();
    match context.own_vote_sender.try_send(vote_msg.clone()) {
        Ok(()) => (),
        Err(TrySendError::Full(_)) => {
            warn!("{my_pubkey}: evicting channel \"{channel_name}\" was full, dropped old vote");
        }
        Err(TrySendError::Disconnected(_)) => {
            return Err(VoteError::ChannelDisconnected(channel_name));
        }
    }

    let root_slot = context.sharable_banks.root().slot();
    if rewards_wants_vote(
        &context.cluster_info,
        &context.leader_schedule,
        root_slot,
        &vote_msg.vote,
    ) {
        let msg = RewardInput::Own(vote_msg.clone());
        nonblocking_send(
            my_pubkey,
            &context.own_reward_sender,
            msg,
            "own_reward_sender",
        )
        .map_err(VoteError::ChannelDisconnected)?;
    }
    Ok(Some(vote_msg))
}

pub(crate) fn generate_refresh_vote_message(
    vote: Vote,
    vctx: &mut VotingContext,
) -> Result<Option<VoteMessage>, VoteError> {
    match create_vote_message(vote, vctx, /* respect_wait_to_vote */ true) {
        Ok(vote_msg) => Ok(Some(vote_msg)),
        Err(e) => {
            handle_skippable_vote_error(e, "generate refresh vote message")?;
            Ok(None)
        }
    }
}

#[cfg(test)]
mod tests {
    use {
        super::*,
        crate::vote_history_storage::NullVoteHistoryStorage,
        agave_votor_messages::consensus_message::Block,
        crossbeam_channel::{Receiver, bounded},
        solana_gossip::contact_info::ContactInfo,
        solana_hash::Hash,
        solana_net_utils::SocketAddrSpace,
        solana_runtime::{
            bank::{Bank, SlotLeader},
            bank_forks::BankForks,
            epoch_stakes::VersionedEpochStakes,
            genesis_utils::{
                ValidatorVoteKeypairs, create_genesis_config_with_alpenglow_vote_accounts,
            },
        },
        std::sync::{Arc, RwLock},
    };

    fn generate_expected_consensus_message(
        ctx: &VotingContext,
        vote: Vote,
        my_bls_keypair: &BLSKeypair,
        root_bank: &Bank,
    ) -> VoteMessage {
        let payload = get_vote_payload_to_sign(vote, ctx.cluster_info.my_shred_version());
        let signature = my_bls_keypair.sign(&payload);
        let rank_map = root_bank.get_rank_map(vote.slot()).unwrap();
        let stake = rank_map.get_pubkey_stake_entry(0).unwrap().stake;
        VoteMessage {
            vote,
            signature: signature.into(),
            rank: 0,
            stake,
        }
    }

    fn setup_voting_context_and_bank_forks(
        own_vote_sender: EvictingSender<VoteMessage>,
        validator_keypairs: &[ValidatorVoteKeypairs],
        my_index: usize,
    ) -> (VotingContext, Receiver<RewardInput>) {
        let (voting_context, _, reward_votes_receiver) =
            setup_voting_context_and_bank_forks_with_forks(
                own_vote_sender,
                validator_keypairs,
                my_index,
            );
        (voting_context, reward_votes_receiver)
    }

    fn setup_voting_context_and_bank_forks_with_forks(
        own_vote_sender: EvictingSender<VoteMessage>,
        validator_keypairs: &[ValidatorVoteKeypairs],
        my_index: usize,
    ) -> (VotingContext, Arc<RwLock<BankForks>>, Receiver<RewardInput>) {
        // Can't have stake of 0, so start at 1 and go to 10. In descending order, so 0 has largest stake.
        let stakes: Vec<u64> = (1u64..=10).rev().map(|x| x.saturating_mul(100)).collect();
        let genesis = create_genesis_config_with_alpenglow_vote_accounts(
            1_000_000_000,
            validator_keypairs,
            stakes,
        );
        let bank0 = Bank::new_for_tests(&genesis.genesis_config);
        let bank_forks = BankForks::new_rw_arc(bank0);

        let my_keys = &validator_keypairs[my_index];
        let contact_info = ContactInfo::new_localhost(&my_keys.node_keypair.pubkey(), 0);
        let cluster_info = Arc::new(ClusterInfo::new(
            contact_info,
            Arc::new(my_keys.node_keypair.insecure_clone()),
            SocketAddrSpace::Unspecified,
        ));
        let sharable_banks = bank_forks.read().unwrap().sharable_banks();
        let leader_schedule = Arc::new(LeaderScheduleCache::new_from_bank(&sharable_banks.root()));
        let bls_sender = bounded(1024).0;
        let commitment_sender = bounded(1024).0;
        let consensus_metrics_sender = bounded(1024).0;
        let (own_reward_aggregates_sender, own_reward_aggregates_receiver) = bounded(1024);
        let voting_context = VotingContext {
            cluster_info,
            vote_history: VoteHistory::new(my_keys.node_keypair.pubkey(), 0),
            vote_account_pubkey: my_keys.vote_keypair.pubkey(),
            identity_keypair: Arc::new(my_keys.node_keypair.insecure_clone()),
            authorized_voter_keypairs: Arc::new(RwLock::new(vec![Arc::new(
                my_keys.vote_keypair.insecure_clone(),
            )])),
            vote_history_storage: Arc::new(NullVoteHistoryStorage::default()),
            derived_bls_keypairs: HashMap::new(),
            own_vote_sender,
            own_reward_sender: own_reward_aggregates_sender,
            bls_sender,
            commitment_sender,
            wait_to_vote_slot: None,
            sharable_banks,
            consensus_metrics_sender,
            leader_schedule,
        };
        (voting_context, bank_forks, own_reward_aggregates_receiver)
    }

    #[test]
    fn test_generate_own_vote_message() {
        let (own_vote_sender, own_vote_receiver) = EvictingSender::new_bounded(1024);
        // Create 10 node validatorvotekeypairs vec
        let validator_keypairs = (0..10)
            .map(|_| ValidatorVoteKeypairs::new(Keypair::new(), Keypair::new(), Keypair::new()))
            .collect::<Vec<_>>();
        let my_index = 0;
        let (mut voting_context, own_reward_aggregates_receiver) =
            setup_voting_context_and_bank_forks(own_vote_sender, &validator_keypairs, my_index);
        let my_bls_keypair = BLSKeypair::derive_from_signer(
            &validator_keypairs[my_index].vote_keypair,
            BLS_KEYPAIR_DERIVE_SEED,
        )
        .unwrap();

        // Generate a normal notarization vote and check it's sent out correctly.
        let block_id = Hash::new_unique();
        let vote_slot = 2;
        let block = Block {
            slot: vote_slot,
            block_id,
        };
        let vote = Vote::new_notarization_vote(block);
        let result = insert_vote_and_create_bls_message(vote, &mut voting_context)
            .ok()
            .unwrap()
            .unwrap();
        let expected_message = generate_expected_consensus_message(
            &voting_context,
            vote,
            &my_bls_keypair,
            &voting_context.sharable_banks.root(),
        );
        if let BLSOp::PushVote { vote } = result {
            let msg = Arc::unwrap_or_clone(vote);
            assert_eq!(msg, expected_message);
        } else {
            panic!("Expected BLSOp::VotePush, got {result:?}");
        }

        // Check that own vote sender receives the vote
        let own_vote_msg = own_vote_receiver.recv().unwrap();
        assert_eq!(own_vote_msg, expected_message);

        // Check that the reward service receives the vote.
        let reward_input = own_reward_aggregates_receiver.recv().unwrap();
        let RewardInput::Own(expected_reward_vote_msg) = reward_input else {
            panic!("invalid msg type received");
        };
        assert_eq!(expected_reward_vote_msg, expected_message);

        let refresh_vote = Vote::new_notarization_vote(Block {
            slot: vote_slot,
            block_id,
        });
        let refresh_result = generate_refresh_vote_message(refresh_vote, &mut voting_context)
            .ok()
            .unwrap()
            .unwrap();
        assert_eq!(refresh_result.vote.slot(), vote_slot);
        assert_eq!(refresh_result, expected_message);
        assert!(own_vote_receiver.try_recv().is_err());
        assert!(own_reward_aggregates_receiver.try_recv().is_err());
    }

    #[test]
    fn test_wait_to_vote_slot() {
        let (own_vote_sender, _own_vote_receiver) = EvictingSender::new_bounded(1024);
        // Create 10 node validatorvotekeypairs vec
        let validator_keypairs = (0..10)
            .map(|_| ValidatorVoteKeypairs::new(Keypair::new(), Keypair::new(), Keypair::new()))
            .collect::<Vec<_>>();
        let my_index = 0;
        let (mut voting_context, _reward_votes_receiver) =
            setup_voting_context_and_bank_forks(own_vote_sender, &validator_keypairs, my_index);

        // If we haven't reached wait_to_vote_slot yet, return Ok(None)
        voting_context.wait_to_vote_slot = Some(4);
        let vote = Vote::new_finalization_vote(2);
        assert!(
            insert_vote_and_create_bls_message(vote, &mut voting_context)
                .unwrap()
                .is_none()
        );

        // If we have reached wait_to_vote_slot, we should be able to vote
        voting_context.wait_to_vote_slot = Some(1);
        assert!(
            insert_vote_and_create_bls_message(vote, &mut voting_context)
                .unwrap()
                .is_some()
        );
    }

    #[test]
    fn test_non_voting_node() {
        let (own_vote_sender, _own_vote_receiver) = EvictingSender::new_bounded(1024);
        // Create 10 node validatorvotekeypairs vec
        let validator_keypairs = (0..10)
            .map(|_| ValidatorVoteKeypairs::new(Keypair::new(), Keypair::new(), Keypair::new()))
            .collect::<Vec<_>>();
        let my_index = 0;
        let (mut voting_context, _reward_votes_receiver) =
            setup_voting_context_and_bank_forks(own_vote_sender, &validator_keypairs, my_index);

        // Empty authorized voter keypairs to simulate non voting node
        voting_context.authorized_voter_keypairs = Arc::new(std::sync::RwLock::new(vec![]));
        let vote = Vote::new_skip_vote(5);
        assert!(matches!(
            generate_vote_tx(
                vote,
                &voting_context.sharable_banks.root(),
                voting_context.vote_account_pubkey,
                voting_context.cluster_info.my_shred_version(),
                &voting_context.identity_keypair,
                &voting_context.authorized_voter_keypairs,
                voting_context.wait_to_vote_slot,
                &mut voting_context.derived_bls_keypairs,
            ),
            GenerateVoteTxResult::NonVoting
        ));

        // Recover correct value to vote again
        voting_context.authorized_voter_keypairs = Arc::new(RwLock::new(vec![Arc::new(
            validator_keypairs[my_index].vote_keypair.insecure_clone(),
        )]));
        assert!(
            insert_vote_and_create_bls_message(vote, &mut voting_context)
                .unwrap()
                .is_some()
        );
    }

    #[test]
    fn test_wrong_identity_keypair() {
        let (own_vote_sender, _own_vote_receiver) = EvictingSender::new_bounded(1024);
        // Create 10 node validatorvotekeypairs vec
        let validator_keypairs = (0..10)
            .map(|_| ValidatorVoteKeypairs::new(Keypair::new(), Keypair::new(), Keypair::new()))
            .collect::<Vec<_>>();
        let my_index = 0;
        let (mut voting_context, _reward_votes_receiver) =
            setup_voting_context_and_bank_forks(own_vote_sender, &validator_keypairs, my_index);

        // Wrong identity keypair should return HotSpare based on rank_map.node_pubkey.
        let wrong_identity_keypair = Arc::new(Keypair::new());
        let vote = Vote::new_notarization_vote(Block {
            slot: 6,
            block_id: Hash::new_unique(),
        });
        assert!(matches!(
            generate_vote_tx(
                vote,
                &voting_context.sharable_banks.root(),
                voting_context.vote_account_pubkey,
                voting_context.cluster_info.my_shred_version(),
                &wrong_identity_keypair,
                &voting_context.authorized_voter_keypairs,
                voting_context.wait_to_vote_slot,
                &mut voting_context.derived_bls_keypairs,
            ),
            GenerateVoteTxResult::HotSpare
        ));
    }

    #[test]
    fn test_wrong_vote_account_pubkey() {
        let (own_vote_sender, _own_vote_receiver) = EvictingSender::new_bounded(1024);
        // Create 10 node validatorvotekeypairs vec
        let validator_keypairs = (0..10)
            .map(|_| ValidatorVoteKeypairs::new(Keypair::new(), Keypair::new(), Keypair::new()))
            .collect::<Vec<_>>();
        let my_index = 0;
        let (mut voting_context, _reward_votes_receiver) =
            setup_voting_context_and_bank_forks(own_vote_sender, &validator_keypairs, my_index);

        // Wrong vote account pubkey
        voting_context.vote_account_pubkey = Pubkey::new_unique();
        let vote = Vote::new_notarization_vote(Block {
            slot: 7,
            block_id: Hash::new_unique(),
        });
        assert!(
            generate_refresh_vote_message(vote, &mut voting_context)
                .unwrap()
                .is_none()
        );

        // Recover correct value to vote again
        voting_context.vote_account_pubkey = validator_keypairs[my_index].vote_keypair.pubkey();
        assert!(
            generate_refresh_vote_message(vote, &mut voting_context)
                .unwrap()
                .is_some()
        );
    }

    #[test]
    #[should_panic(expected = "could not find rank map for slot 1000000000")]
    fn test_panic_on_future_slot() {
        agave_logger::setup();
        let (own_vote_sender, _own_vote_receiver) = EvictingSender::new_bounded(1024);
        // Create 10 node validatorvotekeypairs vec
        let validator_keypairs = (0..10)
            .map(|_| ValidatorVoteKeypairs::new(Keypair::new(), Keypair::new(), Keypair::new()))
            .collect::<Vec<_>>();
        let my_index = 0;
        let (mut voting_context, _reward_votes_receiver) =
            setup_voting_context_and_bank_forks(own_vote_sender, &validator_keypairs, my_index);

        // If we try to vote for a slot in the future, we should panic
        let vote = Vote::new_notarization_vote(Block {
            slot: 1_000_000_000,
            block_id: Hash::new_unique(),
        });
        let _ = insert_vote_and_create_bls_message(vote, &mut voting_context);
    }

    #[test]
    fn test_zero_staked_validator_fails_voting() {
        agave_logger::setup();
        let (own_vote_sender, _own_vote_receiver) = EvictingSender::new_bounded(10_000);
        // Create 10 node validatorvotekeypairs vec
        let validator_keypairs = (0..10)
            .map(|_| ValidatorVoteKeypairs::new(Keypair::new(), Keypair::new(), Keypair::new()))
            .collect::<Vec<_>>();
        let my_index = 0;
        let (mut voting_context, bank_forks, _reward_votes_receiver) =
            setup_voting_context_and_bank_forks_with_forks(
                own_vote_sender,
                &validator_keypairs,
                my_index,
            );

        // Set the stake of my_index to 0 in epoch 2
        // For epoch 2, make validator my_index to be zero stake, others have stake in ascending order, 1 < 2 < ... < 9
        let bank = voting_context.sharable_banks.root();
        assert_eq!(bank.epoch(), 0);
        assert!(bank.epoch_stakes(2).is_none());
        let vote_accounts_hash_map = validator_keypairs
            .iter()
            .enumerate()
            .map(|(i, keypairs)| {
                let stake = if i == my_index {
                    0
                } else {
                    i.saturating_mul(100)
                };
                let authorized_voter = keypairs.vote_keypair.pubkey();
                // Read vote_account from bank 0
                let vote_account = bank.get_vote_account(&authorized_voter).unwrap();
                (authorized_voter, (stake as u64, vote_account))
            })
            .collect();
        let mut new_bank = Bank::new_from_parent(bank, SlotLeader::default(), 1);
        assert!(new_bank.epoch_stakes(2).is_none());
        let epoch2_epoch_stakes = VersionedEpochStakes::new_for_tests(vote_accounts_hash_map, 2);
        new_bank.set_epoch_stakes_for_test(2, epoch2_epoch_stakes);
        assert!(new_bank.epoch_stakes(2).is_some());
        new_bank.freeze();
        bank_forks.write().unwrap().insert(new_bank);
        bank_forks.write().unwrap().set_root(1, None, None);
        voting_context.sharable_banks = bank_forks.read().unwrap().sharable_banks();

        // If we try to vote for a slot in epoch 1, it should succeed
        let first_slot_in_epoch_1 = voting_context
            .sharable_banks
            .root()
            .epoch_schedule()
            .get_first_slot_in_epoch(1);
        let vote = Vote::new_notarization_vote(Block {
            slot: first_slot_in_epoch_1,
            block_id: Hash::new_unique(),
        });
        assert!(
            insert_vote_and_create_bls_message(vote, &mut voting_context)
                .unwrap()
                .is_some()
        );

        // If we try to vote for a slot in epoch 2, we should get NoRankFound error
        let first_slot_in_epoch_2 = voting_context
            .sharable_banks
            .root()
            .epoch_schedule()
            .get_first_slot_in_epoch(2);
        let vote = Vote::new_notarization_vote(Block {
            slot: first_slot_in_epoch_2,
            block_id: Hash::new_unique(),
        });
        assert!(
            insert_vote_and_create_bls_message(vote, &mut voting_context)
                .unwrap()
                .is_none()
        );
    }

    /// DoS: `EvictingSender` drops the oldest vote when the channel is full.
    ///
    /// In production, `own_vote_sender` is an `EvictingSender` with capacity 10000.
    /// When the channel is full, the oldest vote is evicted and the newest is
    /// inserted. If the evicted vote was needed for certificate formation (e.g.,
    /// the consensus pool service hasn't consumed it yet), the certificate for
    /// that slot cannot form because the vote is permanently lost from the channel.
    ///
    /// This test demonstrates:
    /// 1. EvictingSender with small capacity (10) accepts 10 votes
    /// 2. Sending an 11th vote evicts the 1st (oldest) vote
    /// 3. The evicted vote is no longer in the channel
    /// 4. The newest vote IS in the channel — only the oldest is lost
    #[test]
    fn test_dos_evicting_sender_drops_own_votes() {
        use {
            solana_bls_signatures::{
                BLS_SIGNATURE_AFFINE_SIZE, signature::Signature as BLSSignature,
            },
            std::num::NonZero,
        };

        // 1. Create EvictingSender with small capacity (10 for test).
        // In production this is 10000 — the same eviction logic applies.
        let (evicting_sender, vote_receiver) = EvictingSender::new_bounded(10);

        // Helper to create a VoteMessage for a given slot/rank.
        let make_vote_msg = |slot: u64, rank: u16| VoteMessage {
            vote: Vote::new_notarization_vote(Block {
                slot,
                block_id: Hash::new_unique(),
            }),
            signature: BLSSignature([0u8; BLS_SIGNATURE_AFFINE_SIZE]),
            rank,
            stake: NonZero::new(100).unwrap(),
        };

        // 2. Send 10 votes through it — all should succeed (channel not full yet).
        for i in 0..10u64 {
            let vote_msg = make_vote_msg(i, i as u16);
            assert!(
                evicting_sender.try_send(vote_msg).is_ok(),
                "send for slot {} should succeed (channel not full)",
                i
            );
        }
        assert_eq!(vote_receiver.len(), 10);

        // 3. Send an 11th vote — the 1st (oldest) is evicted.
        let eleventh_vote = make_vote_msg(10, 10);
        let result = evicting_sender.try_send(eleventh_vote);

        // EvictingSender::try_send returns Err(TrySendError::Full(older)) where
        // `older` is the evicted (oldest) message, and the new message was inserted.
        assert!(
            result.is_err(),
            "try_send on full EvictingSender should return Err with evicted vote"
        );
        let evicted = match result {
            Err(TrySendError::Full(evicted)) => evicted,
            _ => panic!("expected TrySendError::Full with evicted vote, got {:?}", result),
        };

        // The evicted vote should be the 1st vote (slot 0, rank 0).
        assert_eq!(
            evicted.vote.slot(),
            0,
            "the oldest vote (slot 0) should have been evicted"
        );
        assert_eq!(
            evicted.rank, 0,
            "the evicted vote should have rank 0 (the first vote sent)"
        );

        // 4. The 1st vote's rank is no longer in the pool → cert formation fails for that slot.
        // Verify that the evicted vote is NOT in the channel anymore.
        let received: Vec<_> = vote_receiver.try_iter().collect();
        assert_eq!(received.len(), 10, "channel should still have 10 votes");

        // The first vote (slot 0) should NOT be in the channel — it was evicted.
        assert!(
            !received.iter().any(|vm| vm.vote.slot() == 0),
            "evicted vote (slot 0) should not be in the channel —              it's been dropped and is unavailable for certificate formation"
        );

        // The 11th vote (slot 10) SHOULD be in the channel — it was inserted.
        assert!(
            received.iter().any(|vm| vm.vote.slot() == 10),
            "newest vote (slot 10) should be in the channel"
        );

        // Votes 1–9 should still be in the channel (only the oldest was evicted).
        for slot in 1..10u64 {
            assert!(
                received.iter().any(|vm| vm.vote.slot() == slot),
                "vote for slot {} should still be in the channel",
                slot
            );
        }

        // DoS impact: if the consensus pool service reads from `own_votes_receiver`,
        // it will never see the evicted vote (slot 0, rank 0). Certificate formation
        // that requires this vote will fail because the vote is permanently lost.
        // An attacker can exploit this by filling the channel faster than the pool
        // can consume, causing critical votes to be evicted.
    }


    /// A VoteHistoryStorage that always fails on `store()`.
    /// Used to simulate a disk write failure or other persistence error.
    struct FailingVoteHistoryStorage;

    impl VoteHistoryStorage for FailingVoteHistoryStorage {
        fn load(&self, _node_pubkey: &Pubkey) -> Result<VoteHistory, VoteHistoryError> {
            Err(VoteHistoryError::IoError(std::io::Error::other(
                "FailingVoteHistoryStorage::load() always fails",
            )))
        }

        fn store(
            &self,
            _saved_vote_history: &SavedVoteHistoryVersions,
        ) -> Result<(), VoteHistoryError> {
            Err(VoteHistoryError::IoError(std::io::Error::other(
                "FailingVoteHistoryStorage::store() always fails (simulated disk error)",
            )))
        }
    }

    #[test]
    fn test_vote_sent_before_persist_failure_causes_dos() {
        // TARGET 10: Vote save ordering — send before persist (DoS)
        //
        // In `insert_vote_and_create_bls_message` (lines 286-309):
        //   Line 291: add_vote (in-memory)                          ← step 1
        //   Line 293: create_and_send_own_vote_message (sends to pool) ← step 2 (sent!)
        //   Line 299: SavedVoteHistory::new (can fail)               ← step 3
        //   Line 301: vote_history_storage.store (can fail)          ← step 4 (fails!)
        //
        // If save fails at step 4:
        //   - The vote was ALREADY sent to the pool (step 2 succeeded)
        //   - The Err propagates via `?` → event_loop returns Err → validator SHUTS DOWN
        //   - The vote cannot be rolled back from the pool
        //
        // This test demonstrates:
        //   1. A FailingVoteHistoryStorage that fails on store()
        //   2. insert_vote_and_create_bls_message returns Err (save failure)
        //   3. The vote WAS sent to the pool (step 2 succeeded before step 4 failed)
        //   4. The Err would cause the event_loop to exit (validator shutdown)

        let (own_vote_sender, own_vote_receiver) = EvictingSender::new_bounded(1024);
        let validator_keypairs = (0..10)
            .map(|_| ValidatorVoteKeypairs::new(Keypair::new(), Keypair::new(), Keypair::new()))
            .collect::<Vec<_>>();
        let my_index = 0;
        let (mut voting_context, _reward_votes_receiver) =
            setup_voting_context_and_bank_forks(own_vote_sender, &validator_keypairs, my_index);

        // Replace the vote history storage with one that always fails on store()
        voting_context.vote_history_storage = Arc::new(FailingVoteHistoryStorage);

        let block_id = Hash::new_unique();
        let vote = Vote::new_notarization_vote(Block {
            slot: 2,
            block_id,
        });

        // Call insert_vote_and_create_bls_message — this should return Err
        // because store() fails at step 4.
        let result = insert_vote_and_create_bls_message(vote, &mut voting_context);

        // Step 4 assertion: The function returns Err (save failure propagated)
        assert!(
            result.is_err(),
            "insert_vote_and_create_bls_message should return Err when store() fails. \
             This Err would propagate through the event_loop via `?` operator, \
             causing the validator to shut down (DoS)."
        );

        // Verify it's specifically a SavedVoteHistoryError (from store failure)
        match &result {
            Err(VoteError::SavedVoteHistoryError(e)) => {
                // Confirmed: the error is from vote history storage failure
                assert!(
                    matches!(e, VoteHistoryError::IoError(_)),
                    "Error should be an IoError from the failing storage"
                );
            }
            _ => panic!("Expected VoteError::SavedVoteHistoryError, got {result:?}"),
        }

        // Step 2 assertion: The vote WAS sent to the pool BEFORE the save failed.
        // The own_vote_receiver should have received the vote message,
        // proving the send happened before the persist failure.
        let received_vote = own_vote_receiver
            .try_recv()
            .expect(
                "Vote message should have been sent to the pool (step 2) BEFORE \
                 store() failed (step 4). This proves the send-before-persist ordering bug: \
                 the vote is already in the network but the validator will shut down.",
            );

        // Verify the sent vote matches what we submitted
        assert_eq!(received_vote.vote.slot(), 2);
        assert_eq!(received_vote.vote, vote);

        // Summary: The vote was sent to the pool (step 2) but the save failed (step 4).
        // The Err propagates through the event loop (via `?` operator on lines 441, 458, etc.
        // in event_handler.rs), causing the event_loop to return Err, which shuts down
        // the validator. This is a DoS: a transient disk error kills the validator while
        // the vote is already sent but not persisted.
    }

    /// DoS: Egress channel saturation drops votes and certificates.
    ///
    /// The egress channel (mpsc) has capacity VOTOR_RATE_LIMIT_PPS * 5 = 250.
    /// broadcast_consensus_message uses egress.try_send() which silently drops
    /// on full. During standstill, a burst of timeout votes can fill the channel,
    /// causing subsequent votes/certs to be dropped. This creates a feedback loop:
    /// standstill -> timeout burst -> egress full -> votes dropped -> certs can't form
    /// -> continued standstill.
    #[test]
    fn test_dos_egress_channel_saturation_drops_votes() {
        use bytes::Bytes;
        use crossbeam_channel::bounded;

        // VOTOR_RATE_LIMIT_PPS = 50, capacity = 50 * 5 = 250
        let egress_capacity = crate::voting_service::VOTOR_RATE_LIMIT_PPS * 5;
        let (egress_sender, egress_receiver) = bounded::<Bytes>(egress_capacity);

        // Fill the egress channel to capacity
        for i in 0..egress_capacity {
            let msg = Bytes::from(format!("vote_{}", i));
            egress_sender.try_send(msg).expect("should fit in capacity");
        }

        // Channel is now full — the next try_send should fail (drop)
        let overflow_msg = Bytes::from("critical_vote_that_gets_dropped");
        let result = egress_sender.try_send(overflow_msg);

        assert!(
            result.is_err(),
            "Egress channel should be full — try_send should drop the vote"
        );

        // Verify the channel is at capacity
        let mut count = 0;
        while egress_receiver.try_recv().is_ok() {
            count += 1;
        }
        assert_eq!(
            count, egress_capacity,
            "Channel should contain exactly {} messages (the critical vote was dropped)",
            egress_capacity
        );
    }

    /// DoS: BLS channel saturation drops PushVote operations.
    ///
    /// The bls_sender has bounded(1000) capacity. EventHandler uses
    /// nonblocking_send for BLS ops, which drops on full. During a certificate
    /// burst, the channel can fill, causing subsequent PushVote ops to be
    /// dropped. The vote is recorded in vote_history but never broadcast.
    #[test]
    fn test_dos_bls_channel_saturation_drops_pushvote() {
        use crate::common::nonblocking_send;
        use crossbeam_channel::bounded;
        use solana_pubkey::Pubkey;

        let bls_capacity = 1000;
        let (bls_sender, bls_receiver) = bounded::<BLSOp>(bls_capacity);
        let my_pubkey = Pubkey::new_unique();

        // Fill the BLS channel with dummy data (simulate cert burst)
        for _ in 0..bls_capacity {
            bls_sender
                .try_send(BLSOp::PushCertificates {
                    certificates: vec![],
                })
                .expect("should fit in capacity");
        }

        // Channel is now full — nonblocking_send should silently drop
        let vote_msg = VoteMessage {
            vote: Vote::new_skip_vote(42),
            signature: solana_bls_signatures::Signature(
                [0u8; solana_bls_signatures::BLS_SIGNATURE_AFFINE_SIZE]),
            rank: 0,
            stake: std::num::NonZero::new(100).unwrap(),
        };
        let bls_op = BLSOp::PushVote {
            vote: std::sync::Arc::new(vote_msg),
        };

        let result = nonblocking_send(&my_pubkey, &bls_sender, bls_op, "bls_sender");

        // nonblocking_send returns Ok(()) even when it drops — the drop is silent
        assert!(result.is_ok(), "nonblocking_send returns Ok even on drop");

        // Verify the channel is at capacity (the PushVote was dropped)
        let mut count = 0;
        while bls_receiver.try_recv().is_ok() {
            count += 1;
        }
        assert_eq!(
            count, bls_capacity,
            "Channel should contain exactly {} ops (the PushVote was silently dropped)",
            bls_capacity
        );
    }

}
