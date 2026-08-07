use {
    crate::block_creation_loop::rewards::msg_types::{
        RewardRequest, RewardRespSucc, RewardResponse,
    },
    agave_bls_sigverify::rewards::RewardInput,
    agave_votor_messages::reward_certificate::{BuildRewardCertsRespError, NUM_SLOTS_FOR_REWARD},
    crossbeam_channel::RecvError,
    entry::Entry,
    solana_clock::Slot,
    solana_gossip::cluster_info::ClusterInfo,
    solana_runtime::bank::Bank,
    std::{collections::BTreeMap, sync::Arc},
};

mod entry;

/// Container to store state needed to generate reward certificates.
pub(super) struct CertsBuilder {
    /// Per [`Slot`], stores the skip and notar votes.
    aggregates: BTreeMap<Slot, Entry>,
    /// Stores the latest pubkey for the current node.
    cluster_info: Arc<ClusterInfo>,
}

impl CertsBuilder {
    /// Constructs a new instance of [`CertsBuilder`].
    pub(super) fn new(cluster_info: Arc<ClusterInfo>) -> Self {
        Self {
            aggregates: BTreeMap::default(),
            cluster_info,
        }
    }

    /// Builds reward certificates.
    fn build_certs(
        &mut self,
        bank_slot: Slot,
    ) -> Result<RewardRespSucc, BuildRewardCertsRespError> {
        let Some(reward_slot) = bank_slot.checked_sub(NUM_SLOTS_FOR_REWARD) else {
            return Ok(RewardRespSucc::default());
        };
        // we assume that the block creation loop will only ever request to build reward certs in a
        // strictly increasing order so we can drop older state
        self.aggregates = self.aggregates.split_off(&reward_slot);
        match self.aggregates.remove(&reward_slot) {
            None => Ok(RewardRespSucc::default()),
            Some(entry) => entry.build_certs(reward_slot),
        }
    }

    pub(super) fn build_request(
        &mut self,
        request: Result<RewardRequest, RecvError>,
    ) -> Result<(), ()> {
        let my_pubkey = self.cluster_info.id();
        match request {
            Ok(RewardRequest {
                bank_slot,
                reply_sender,
            }) => {
                let resp = RewardResponse {
                    result: self.build_certs(bank_slot),
                };
                let _ = reply_sender.send(resp).inspect_err(|_| {
                    info!(
                        "{my_pubkey}: channel to send reply for bank_slot={bank_slot} disconnected"
                    );
                });
                Ok(())
            }
            Err(_) => {
                error!("{my_pubkey}: build reward certs channel is disconnected; exiting.");
                Err(())
            }
        }
    }

    pub(super) fn handle_input(&mut self, root_bank: &Bank, input: RewardInput) {
        let root_slot = root_bank.slot();
        // drop state that is too old based on how the root slot has progressed
        // TODO: if this actually purges state, that probably indicates that the leader missed its
        // window.  We should have a metric for this.
        self.aggregates = self
            .aggregates
            .split_off(&root_slot.saturating_sub(NUM_SLOTS_FOR_REWARD));

        match input {
            RewardInput::External(aggregates) => {
                for aggregate in aggregates {
                    let slot = aggregate.vote().slot();
                    let Some(rank_map) = root_bank.get_rank_map(slot) else {
                        warn!(
                            "failed to look up rank_map for slot {slot} using bank for slot {}",
                            root_bank.slot()
                        );
                        return;
                    };
                    let max_validators = rank_map.len();
                    let mut vote_account_pubkeys = vec![];
                    for rank in aggregate.ranks().iter_ones() {
                        let Some(stake_entry) = rank_map.get_pubkey_stake_entry(rank) else {
                            return;
                        };
                        vote_account_pubkeys.push(stake_entry.vote_account_pubkey);
                    }

                    let vote = *aggregate.vote();
                    match self
                        .aggregates
                        .entry(aggregate.vote().slot())
                        .or_insert_with(|| Entry::new(max_validators))
                        .add_aggregate(aggregate, vote_account_pubkeys)
                    {
                        Ok(()) => (),
                        Err(e) => {
                            warn!("Adding aggregate with vote {vote:?} failed with {e}");
                        }
                    }
                }
            }
            RewardInput::Own(vote_msg) => {
                let slot = vote_msg.vote.slot();
                let Some(rank_map) = root_bank.get_rank_map(slot) else {
                    warn!(
                        "failed to look up rank_map for slot {slot} using bank for slot {}",
                        root_bank.slot()
                    );
                    return;
                };
                let max_validators = rank_map.len();
                let Some(stake_entry) = rank_map.get_pubkey_stake_entry(vote_msg.rank as usize)
                else {
                    return;
                };

                let vote = vote_msg.vote;
                match self
                    .aggregates
                    .entry(vote_msg.vote.slot())
                    .or_insert_with(|| Entry::new(max_validators))
                    .add_own_msg(vote_msg, stake_entry.vote_account_pubkey)
                {
                    Ok(()) => (),
                    Err(e) => {
                        warn!("Adding aggregate with vote {vote:?} failed with {e}");
                    }
                }
            }
        }
    }
}


#[cfg(test)]
mod dos_tests {
    use {
        super::*,
        agave_votor_messages::reward_certificate::NUM_SLOTS_FOR_REWARD,
        solana_gossip::{cluster_info::ClusterInfo, node::Node},
        solana_keypair::Keypair,
        solana_net_utils::SocketAddrSpace,
        solana_signer::Signer,
        std::sync::Arc,
    };

    fn make_cluster_info() -> Arc<ClusterInfo> {
        let keypair = Arc::new(Keypair::new());
        Arc::new(ClusterInfo::new(
            Node::new_localhost_with_pubkey(&keypair.pubkey()).info,
            keypair,
            SocketAddrSpace::Unspecified,
        ))
    }

    /// DoS: CertsBuilder in-memory state lost on restart.
    ///
    /// `CertsBuilder` stores vote aggregates in an in-memory `BTreeMap<Slot, Entry>`.
    /// There is **no persistence mechanism** — no save, no serialization, no disk backup.
    ///
    /// When the validator process restarts, a new `CertsBuilder` is constructed with an
    /// empty `BTreeMap`.  All previously accumulated aggregates for up to
    /// `NUM_SLOTS_FOR_REWARD` (8) slots are permanently lost.
    ///
    /// This means the leader cannot build reward certificates for those slots, causing
    /// validators who voted in those slots to miss their rewards — a denial-of-service
    /// on the reward distribution mechanism.
    #[test]
    fn test_dos_certs_builder_state_lost_on_restart() {
        let cluster_info = make_cluster_info();

        // --- Step 1: Create CertsBuilder, add some aggregates ---
        let mut builder_before = CertsBuilder::new(cluster_info.clone());

        // Simulate having accumulated vote aggregates for several slots by
        // directly inserting Entry objects into the in-memory BTreeMap.
        // In production, these would be populated via `handle_input`.
        let reward_slots: Vec<Slot> = (1..=NUM_SLOTS_FOR_REWARD).collect();
        for &slot in &reward_slots {
            builder_before.aggregates.insert(slot, Entry::new(10));
        }

        // --- Step 2: Show that the aggregates are in-memory only (no persistence) ---
        // The aggregates BTreeMap has entries for all reward slots.
        assert_eq!(builder_before.aggregates.len(), NUM_SLOTS_FOR_REWARD as usize);
        for &slot in &reward_slots {
            assert!(
                builder_before.aggregates.contains_key(&slot),
                "aggregates should contain slot {slot}"
            );
        }

        // There is no save/persist/serialize method on CertsBuilder.
        // The struct stores only `aggregates: BTreeMap<Slot, Entry>` and `cluster_info: Arc<ClusterInfo>`.
        // Neither field is persisted to disk.

        // --- Step 3: Simulate restart by creating a new CertsBuilder ---
        let builder_after = CertsBuilder::new(cluster_info);

        // --- Step 4: Show the aggregates are lost → reward certs can't be built ---
        // The new CertsBuilder starts with an empty BTreeMap.
        assert!(
            builder_after.aggregates.is_empty(),
            "after restart, CertsBuilder should have no aggregates — all in-memory state is lost"
        );

        // Calling build_certs on the new builder for any bank_slot that would need
        // a reward_slot from the lost aggregates returns empty/default results.
        // E.g., bank_slot = reward_slots[0] + NUM_SLOTS_FOR_REWARD would need
        // aggregates at reward_slots[0], but they are gone.
        let mut builder_after_mut = builder_after;
        for &slot in &reward_slots {
            let bank_slot = slot + NUM_SLOTS_FOR_REWARD;
            let result = builder_after_mut.build_certs(bank_slot).unwrap();
            assert!(
                result.skip.is_none() && result.notar.is_none() && result.validators.is_empty(),
                "build_certs for bank_slot={bank_slot} (reward_slot={slot}) \
                 should return empty results after restart — aggregates were lost"
            );
        }

        // In contrast, the original builder still has the aggregates and would
        // find the Entry when build_certs is called (even if the Entry has no
        // actual votes, the Entry is found rather than returning default early).
        for &slot in &reward_slots {
            let bank_slot = slot + NUM_SLOTS_FOR_REWARD;
            // build_certs consumes the Entry from the BTreeMap
            let _result = builder_before.build_certs(bank_slot).unwrap();
            // With an empty Entry (no votes), build_certs returns default too,
            // but the critical difference is that the Entry was FOUND and processed.
            // After restart, the Entry doesn't exist at all.
            assert!(
                builder_before.aggregates.get(&slot).is_none(),
                "build_certs should have consumed the Entry for slot {slot}"
            );
        }
    }

    /// DoS: Reward cert window lost after restart — up to NUM_SLOTS_FOR_REWARD slots affected.
    ///
    /// This test demonstrates the blast radius: exactly NUM_SLOTS_FOR_REWARD (8) slots
    /// of reward certificates cannot be produced after a restart.
    #[test]
    fn test_dos_restart_loses_num_slots_for_reward_window() {
        let cluster_info = make_cluster_info();

        // Populate a builder with aggregates for a full reward window.
        let mut builder = CertsBuilder::new(cluster_info.clone());
        let first_reward_slot: Slot = 100;
        for i in 0..NUM_SLOTS_FOR_REWARD {
            builder
                .aggregates
                .insert(first_reward_slot + i, Entry::new(10));
        }
        assert_eq!(builder.aggregates.len(), NUM_SLOTS_FOR_REWARD as usize);

        // Simulate restart.
        let mut builder_after_restart = CertsBuilder::new(cluster_info);

        // Every slot in the reward window is now unbuildable.
        let mut unbuildable_slots = 0;
        for i in 0..NUM_SLOTS_FOR_REWARD {
            let reward_slot = first_reward_slot + i;
            let bank_slot = reward_slot + NUM_SLOTS_FOR_REWARD;
            let result = builder_after_restart.build_certs(bank_slot).unwrap();
            if result.skip.is_none() && result.notar.is_none() && result.validators.is_empty() {
                unbuildable_slots += 1;
            }
        }

        // All NUM_SLOTS_FOR_REWARD slots are unbuildable after restart.
        assert_eq!(
            unbuildable_slots,
            NUM_SLOTS_FOR_REWARD,
            "all {NUM_SLOTS_FOR_REWARD} reward slots should be unbuildable after restart"
        );
    }
}
