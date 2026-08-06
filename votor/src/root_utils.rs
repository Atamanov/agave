use {
    crate::{
        commitment::{CommitmentType, update_commitment_cache},
        common::nonblocking_send,
        event_handler::PendingBlocks,
        voting_utils::VotingContext,
        votor::SharedContext,
    },
    agave_votor_messages::consensus_message::Block,
    crossbeam_channel::Sender,
    solana_clock::Slot,
    solana_hash::Hash,
    solana_ledger::{blockstore::Blockstore, leader_schedule_cache::LeaderScheduleCache},
    solana_pubkey::Pubkey,
    solana_rpc::{
        optimistically_confirmed_bank_tracker::{BankNotification, BankNotificationSenderConfig},
        rpc_subscriptions::RpcSubscriptions,
    },
    solana_runtime::{
        bank_forks::BankForks, bank_forks_controller::BankForksController,
        installed_scheduler_pool::BankWithScheduler, snapshot_controller::SnapshotController,
    },
    solana_time_utils::timestamp,
    std::{
        collections::BTreeSet,
        sync::{Arc, RwLock},
    },
};

/// Structures that are not used in the event loop, but need to be updated
/// or notified when setting root
pub(crate) struct RootContext {
    pub(crate) bank_notification_sender: Option<BankNotificationSenderConfig>,
    pub(crate) bank_forks_controller: Arc<dyn BankForksController>,
}

/// Sets the root for the votor event handling loop. Handles rooting all things
/// except the certificate pool
pub(crate) fn set_root(
    my_pubkey: &Pubkey,
    new_root: Block,
    bank_hash: Hash,
    ctx: &SharedContext,
    vctx: &mut VotingContext,
    rctx: &RootContext,
    pending_blocks: &mut PendingBlocks,
    finalized_blocks: &mut BTreeSet<Block>,
    received_shred: &mut BTreeSet<Slot>,
) {
    let new_root_slot = new_root.slot;
    info!("{my_pubkey}: setting root {new_root:?}");
    vctx.vote_history.set_root(new_root_slot);
    *pending_blocks = pending_blocks.split_off(&new_root_slot);
    *finalized_blocks = finalized_blocks.split_off(&Block {
        slot: new_root_slot,
        block_id: Hash::default(),
    });
    *received_shred = received_shred.split_off(&new_root_slot);

    rctx.bank_forks_controller.enqueue_set_root(new_root);

    if let Err(e) = ctx.blockstore.insert_optimistic_slot(
        new_root_slot,
        &bank_hash,
        timestamp().try_into().unwrap(),
    ) {
        error!("failed to record optimistic slot in blockstore: slot={new_root_slot}: {e:?}");
    }

    update_commitment_cache(
        my_pubkey,
        CommitmentType::Rooted,
        new_root_slot,
        &vctx.commitment_sender,
    );

    // It is critical to send the OC notification in order to keep compatibility with
    // the RPC API. Additionally the PrioritizationFeeCache relies on this notification
    // in order to perform cleanup. In the future we will look to deprecate OC and remove
    // these code paths.
    if let Some(config) = &rctx.bank_notification_sender {
        let dependency_work = config
            .dependency_tracker
            .as_ref()
            .map(|s| s.get_current_declared_work());
        if let Err(chanel_name) = nonblocking_send(
            my_pubkey,
            &config.sender,
            (
                BankNotification::OptimisticallyConfirmed(new_root_slot, bank_hash),
                dependency_work,
            ),
            "bank_notification_sender",
        ) {
            info!("{my_pubkey}: channel {chanel_name} disconnected");
        }
    }
}

/// Sets the new root, additionally performs the callback after setting the bank forks root
/// During this transition period where both replay stage and voting loop can root depending on the feature flag we
/// have a callback that cleans up progress map and other tower bft structures. Then the callgraph is
///
/// ReplayStage::check_and_handle_new_root -> root_utils::check_and_handle_new_root(callback)
///                                                             |
///                                                             v
/// ReplayStage::handle_new_root           -> root_utils::set_bank_forks_root(callback) -> callback()
///
/// Votor does not need the progress map or other tower bft structures, so it will not use the callback.
#[allow(clippy::too_many_arguments)]
pub fn check_and_handle_new_root<CB>(
    parent_slot: Slot,
    new_root: Slot,
    snapshot_controller: Option<&SnapshotController>,
    highest_super_majority_root: Option<Slot>,
    bank_notification_sender: &Option<BankNotificationSenderConfig>,
    drop_bank_sender: &Sender<Vec<BankWithScheduler>>,
    blockstore: &Blockstore,
    leader_schedule_cache: &Arc<LeaderScheduleCache>,
    bank_forks: &RwLock<BankForks>,
    rpc_subscriptions: Option<&RpcSubscriptions>,
    my_pubkey: &Pubkey,
    callback: CB,
) where
    CB: FnOnce(&BankForks),
{
    // get the root bank before squash
    let root_bank = bank_forks
        .read()
        .unwrap()
        .get(new_root)
        .expect("Root bank doesn't exist");
    let mut rooted_banks = root_bank.parents();
    let oldest_parent = rooted_banks.last().map(|last| last.parent_slot());
    rooted_banks.push(root_bank.clone());
    let rooted_slots: Vec<_> = rooted_banks.iter().map(|bank| bank.slot()).collect();
    let rooted_slot_notifications = bank_notification_sender
        .as_ref()
        .is_some_and(|sender| sender.should_send_parents)
        .then(|| {
            let new_chain = rooted_banks
                .iter()
                .map(|bank| (bank.slot(), bank.bank_id()))
                .collect();
            (new_chain, oldest_parent.unwrap_or(parent_slot))
        });

    // Call leader schedule_cache.set_root() before blockstore.set_root() because
    // bank_forks.root is consumed by repair_service to update gossip, so we don't want to
    // get shreds for repair on gossip before we update leader schedule, otherwise they may
    // get dropped.
    leader_schedule_cache.set_root(rooted_banks.last().unwrap());
    blockstore
        .set_roots(rooted_slots.iter())
        .expect("Ledger set roots failed");
    set_bank_forks_root(
        my_pubkey,
        new_root,
        bank_forks,
        snapshot_controller,
        highest_super_majority_root,
        drop_bank_sender,
        callback,
    );
    blockstore.slots_stats.mark_rooted(new_root);
    if let Some(rpc_subscriptions) = rpc_subscriptions {
        rpc_subscriptions.notify_roots(rooted_slots);
    }
    if let Some(sender) = bank_notification_sender {
        let dependency_work = sender
            .dependency_tracker
            .as_ref()
            .map(|s| s.get_current_declared_work());
        if let Err(channel_name) = nonblocking_send(
            my_pubkey,
            &sender.sender,
            (BankNotification::NewRootBank(root_bank), dependency_work),
            "bank_notification_sender",
        ) {
            info!("{my_pubkey} channel {channel_name} disconnected");
        }
        if let Some((new_chain, oldest_parent)) = rooted_slot_notifications {
            let dependency_work = sender
                .dependency_tracker
                .as_ref()
                .map(|s| s.get_current_declared_work());
            if let Err(channel_name) = nonblocking_send(
                my_pubkey,
                &sender.sender,
                (
                    BankNotification::NewRootedChain(new_chain, oldest_parent),
                    dependency_work,
                ),
                "bank_notification_sender",
            ) {
                info!("{my_pubkey} channel {channel_name} disconnected");
            }
        }
    }
    info!("{my_pubkey}: new root {new_root}");
}

/// Sets the bank forks root:
/// - Prune the program cache
/// - Prune bank forks and drop the removed banks
/// - Calls the callback for use in replay stage and tests
pub fn set_bank_forks_root<CB>(
    my_pubkey: &Pubkey,
    new_root: Slot,
    bank_forks: &RwLock<BankForks>,
    snapshot_controller: Option<&SnapshotController>,
    highest_super_majority_root: Option<Slot>,
    drop_bank_sender: &Sender<Vec<BankWithScheduler>>,
    callback: CB,
) where
    CB: FnOnce(&BankForks),
{
    let banks_to_remove: Vec<_> = {
        let bank_forks = bank_forks.read().unwrap();
        bank_forks
            .get_non_rooted(new_root, highest_super_majority_root)
            .filter_map(|slot| bank_forks.get_with_scheduler(slot))
            .collect()
    };
    for bank in banks_to_remove {
        let _ = bank.wait_for_completed_scheduler();
    }

    bank_forks.read().unwrap().prune_program_cache(new_root);
    let removed_banks = bank_forks.write().unwrap().set_root(
        new_root,
        snapshot_controller,
        highest_super_majority_root,
    );

    if let Err(channel_name) = nonblocking_send(
        my_pubkey,
        drop_bank_sender,
        removed_banks,
        "drop_bank_sender",
    ) {
        info!("{my_pubkey} channel {channel_name} disconnected");
    }
    let r_bank_forks = bank_forks.read().unwrap();
    callback(&r_bank_forks);
}


#[cfg(test)]
mod dos_tests {
    use {
        agave_votor_messages::consensus_message::Block,
        solana_hash::Hash,
        solana_pubkey::Pubkey,
        solana_runtime::{
            bank::Bank,
            bank_forks::BankForks,
            bank_forks_controller::{BankForksController, BankForksControllerHandle},
            genesis_utils::create_genesis_config,
        },
        crate::vote_history::VoteHistory,
    };

    /// DoS: Root divergence via async coalescing.
    ///
    /// In `root_utils::set_root`, `vote_history.set_root(new_root_slot)` is called
    /// **synchronously** (line ~52), while `bank_forks_controller.enqueue_set_root(new_root)`
    /// is called **asynchronously** with no failure feedback.
    ///
    /// `BankForksControllerHandle::enqueue_set_root` coalesces pending roots: only the
    /// **highest** pending root is kept.  If that highest root later fails
    /// `matches_frozen_bank` during replay, all coalesced (lower) roots are silently lost.
    ///
    /// This leaves `vote_history.root` permanently **ahead** of `bank_forks.root` until
    /// a yet-higher root succeeds — a divergence that can stall finalization.
    #[test]
    fn test_dos_root_divergence_via_async_coalescing() {
        // --- Setup: BankForks rooted at slot 0 ---
        let genesis = create_genesis_config(10_000);
        let bank_forks = BankForks::new_rw_arc(Bank::new_for_tests(&genesis.genesis_config));
        assert_eq!(bank_forks.read().unwrap().root(), 0);

        // Simulate a VoteHistory; root_utils::set_root calls vote_history.set_root SYNC.
        let mut vote_history = VoteHistory::new(Pubkey::new_unique(), 0);

        // Create the async BankForksControllerHandle (the coalescing controller).
        let (controller, receiver) = BankForksControllerHandle::new();

        // --- Step 1: Enqueue root at slot 5, then slot 3 (3 is coalesced away) ---
        let block_id_5 = Hash::new_unique();
        let block_id_3 = Hash::new_unique();

        // Simulate root_utils::set_root for slot 5:
        //   vote_history.set_root(5)         // SYNC — updates immediately
        //   controller.enqueue_set_root(5)   // ASYNC — pending
        vote_history.set_root(5);
        controller.enqueue_set_root(Block { slot: 5, block_id: block_id_5 });

        // Simulate root_utils::set_root for slot 3:
        //   vote_history.set_root(3)         // SYNC — but 3 < 5, so vote_history stays at 5
        //   controller.enqueue_set_root(3)   // ASYNC — coalesced away because 3 < 5
        //
        // NOTE: In practice set_root(3) after set_root(5) would not advance vote_history
        // because set_root unconditionally sets root = max(existing, new).  But the
        // enqueue_set_root for 3 is still coalesced away in the controller.
        controller.enqueue_set_root(Block { slot: 3, block_id: block_id_3 });

        // --- Step 2: Process slot 5 — make it fail matches_frozen_bank ---
        // The replay stage would call `receiver.take_set_root_command()` and then check
        // `matches_frozen_bank`.  Since no frozen bank exists at slot 5, it fails.
        let pending_command = receiver.take_set_root_command().unwrap();
        assert_eq!(pending_command.new_root.slot, 5);
        assert_eq!(pending_command.new_root.block_id, block_id_5);

        // No frozen bank at slot 5 → matches_frozen_bank returns false.
        assert!(!pending_command.matches_frozen_bank(&bank_forks.read().unwrap()));

        // --- Step 3: Show slot 3 was lost (coalesced away) ---
        // The second take_set_root_command returns None — slot 3 was never queued.
        assert!(receiver.take_set_root_command().is_none());

        // --- Step 4: Show vote_history root=5 but bank_forks root is still 0 ---
        assert_eq!(vote_history.root(), 5);
        assert_eq!(bank_forks.read().unwrap().root(), 0);

        // The divergence: vote_history thinks root is 5, but BankForks is still at 0.
        // Slot 3 was coalesced away and can never be processed.
        // This divergence persists until a root > 5 is successfully enqueued and processed.
        assert!(
            vote_history.root() > bank_forks.read().unwrap().root(),
            "vote_history root ({}) should be ahead of bank_forks root ({}) — divergence!",
            vote_history.root(),
            bank_forks.read().unwrap().root()
        );
    }

    /// DoS: Multiple lower roots coalesced away when highest root fails.
    ///
    /// Roots 3, 5, 7, 10 are enqueued in increasing order (each from a separate
    /// `root_utils::set_root` call). The coalescing controller only keeps the
    /// highest pending root (10). When 10 fails `matches_frozen_bank`, roots
    /// 3, 5, and 7 are all permanently lost — they were coalesced away.
    #[test]
    fn test_dos_multiple_roots_lost_via_coalescing() {
        let genesis = create_genesis_config(10_000);
        let bank_forks = BankForks::new_rw_arc(Bank::new_for_tests(&genesis.genesis_config));

        let (controller, receiver) = BankForksControllerHandle::new();
        let mut vote_history = VoteHistory::new(Pubkey::new_unique(), 0);

        // Simulate root_utils::set_root being called for slots 3, 5, 7, 10 in order.
        // Each call: vote_history.set_root(slot) SYNC, enqueue_set_root(slot) ASYNC.
        // The coalescing controller only keeps the highest pending root.
        for slot in [3u64, 5, 7, 10] {
            vote_history.set_root(slot);
            controller.enqueue_set_root(Block {
                slot,
                block_id: Hash::new_unique(),
            });
        }

        // Only slot 10 is pending (3, 5, 7 were coalesced away).
        let cmd = receiver.take_set_root_command().unwrap();
        assert_eq!(cmd.new_root.slot, 10);
        assert!(receiver.take_set_root_command().is_none());

        // Slot 10 fails matches_frozen_bank (no frozen bank at slot 10).
        assert!(!cmd.matches_frozen_bank(&bank_forks.read().unwrap()));

        // vote_history advanced to 10 (last set_root call), but bank_forks
        // is still at 0. Slots 3, 5, 7 were coalesced away and are permanently
        // lost — they can never be processed by the replay stage.
        assert_eq!(vote_history.root(), 10);
        assert_eq!(bank_forks.read().unwrap().root(), 0);
    }
}

