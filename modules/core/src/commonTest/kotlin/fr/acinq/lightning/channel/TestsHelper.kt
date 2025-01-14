package fr.acinq.lightning.channel

import fr.acinq.bitcoin.*
import fr.acinq.lightning.*
import fr.acinq.lightning.Lightning.randomBytes32
import fr.acinq.lightning.blockchain.*
import fr.acinq.lightning.blockchain.electrum.WalletState
import fr.acinq.lightning.blockchain.fee.FeeratePerKw
import fr.acinq.lightning.blockchain.fee.OnChainFeerates
import fr.acinq.lightning.channel.states.*
import fr.acinq.lightning.crypto.KeyManager
import fr.acinq.lightning.db.ChannelCloseOutgoingPayment
import fr.acinq.lightning.db.ChannelCloseOutgoingPayment.ChannelClosingType
import fr.acinq.lightning.json.JsonSerializers
import fr.acinq.lightning.logging.MDCLogger
import fr.acinq.lightning.logging.mdc
import fr.acinq.lightning.payment.OutgoingPaymentPacket
import fr.acinq.lightning.serialization.channel.Serialization
import fr.acinq.lightning.tests.TestConstants
import fr.acinq.lightning.tests.utils.testLoggerFactory
import fr.acinq.lightning.transactions.Transactions
import fr.acinq.lightning.utils.*
import fr.acinq.lightning.wire.*
import kotlinx.coroutines.CompletableDeferred
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.runBlocking
import kotlinx.serialization.encodeToString
import kotlin.test.*

// LN Message
internal inline fun <reified T : LightningMessage> List<ChannelAction>.findOutgoingMessages(): List<T> = filterIsInstance<ChannelAction.Message.Send>().map { it.message }.filterIsInstance<T>()
internal inline fun <reified T : LightningMessage> List<ChannelAction>.findOutgoingMessageOpt(): T? = findOutgoingMessages<T>().firstOrNull()
internal inline fun <reified T : LightningMessage> List<ChannelAction>.findOutgoingMessage(): T = findOutgoingMessageOpt<T>() ?: fail("cannot find outgoing message ${T::class}")
internal inline fun <reified T : LightningMessage> List<ChannelAction>.hasOutgoingMessage() = assertNotNull(findOutgoingMessageOpt<T>(), "cannot find outgoing message ${T::class}")

// Blockchain Watches
internal inline fun <reified T : Watch> List<ChannelAction>.findWatches(): List<T> = filterIsInstance<ChannelAction.Blockchain.SendWatch>().map { it.watch }.filterIsInstance<T>()
internal inline fun <reified T : Watch> List<ChannelAction>.findWatch(): T = findWatches<T>().firstOrNull() ?: fail("cannot find watch ${T::class}")
internal inline fun <reified T : Watch> List<ChannelAction>.hasWatch() = assertNotNull(findWatches<T>().firstOrNull(), "cannot find watch ${T::class}")
internal fun List<ChannelAction>.hasWatchFundingSpent(txId: TxId): WatchSpent = hasWatch<WatchSpent>().also { assertEquals(txId, it.txId); assertEquals(BITCOIN_FUNDING_SPENT, it.event) }
internal fun List<ChannelAction>.hasWatchConfirmed(txId: TxId): WatchConfirmed = assertNotNull(findWatches<WatchConfirmed>().firstOrNull { it.txId == txId })

// Commands
internal inline fun <reified T : ChannelCommand> List<ChannelAction>.findCommands(): List<T> = filterIsInstance<ChannelAction.Message.SendToSelf>().map { it.command }.filterIsInstance<T>()
internal inline fun <reified T : ChannelCommand> List<ChannelAction>.findCommandOpt(): T? = findCommands<T>().firstOrNull()
internal inline fun <reified T : ChannelCommand> List<ChannelAction>.findCommand(): T = findCommandOpt<T>() ?: fail("cannot find command ${T::class}")
internal inline fun <reified T : ChannelCommand> List<ChannelAction>.hasCommand() = assertNotNull(findCommandOpt<T>(), "cannot find command ${T::class}")

// Transactions
internal fun List<ChannelAction>.findPublishTxs(): List<Transaction> = filterIsInstance<ChannelAction.Blockchain.PublishTx>().map { it.tx }
internal fun List<ChannelAction>.hasPublishTx(tx: Transaction) = assertContains(findPublishTxs(), tx)
internal fun List<ChannelAction>.hasPublishTx(txType: ChannelAction.Blockchain.PublishTx.Type): Transaction = assertNotNull(filterIsInstance<ChannelAction.Blockchain.PublishTx>().firstOrNull { it.txType == txType }).tx

internal inline fun <reified T : ChannelException> List<ChannelAction>.findCommandErrorOpt(): T? {
    val cmdAddError = filterIsInstance<ChannelAction.ProcessCmdRes.AddFailed>().map { it.error }.filterIsInstance<T>().firstOrNull()
    val otherCmdError = filterIsInstance<ChannelAction.ProcessCmdRes.NotExecuted>().map { it.t }.filterIsInstance<T>().firstOrNull()
    return cmdAddError ?: otherCmdError
}

internal inline fun <reified T : ChannelException> List<ChannelAction>.findCommandError(): T = findCommandErrorOpt<T>() ?: fail("cannot find command error ${T::class}")
internal inline fun <reified T : ChannelException> List<ChannelAction>.hasCommandError() = assertNotNull(findCommandErrorOpt<T>(), "cannot find command error ${T::class}")

internal inline fun <reified T : ChannelAction> List<ChannelAction>.findOpt(): T? = filterIsInstance<T>().firstOrNull()
internal inline fun <reified T : ChannelAction> List<ChannelAction>.find() = findOpt<T>() ?: fail("cannot find action ${T::class}")
internal inline fun <reified T : ChannelAction> List<ChannelAction>.has() = assertTrue { any { it is T } }
internal inline fun <reified T : ChannelAction> List<ChannelAction>.doesNotHave() = assertTrue { none { it is T } }

fun <S : ChannelState> LNChannel<S>.updateFeerate(feerate: FeeratePerKw): LNChannel<S> = this.copy(ctx = this.ctx.copy(onChainFeerates = MutableStateFlow(OnChainFeerates(feerate, feerate, feerate, feerate))))

fun Features.add(vararg pairs: Pair<Feature, FeatureSupport>): Features = this.copy(activated = this.activated + mapOf(*pairs))
fun Features.remove(vararg features: Feature): Features = this.copy(activated = activated.filterKeys { f -> !features.contains(f) })

data class LNChannel<out S : ChannelState>(
    val ctx: ChannelContext,
    val state: S
) {
    val staticParams = ctx.staticParams
    val currentBlockHeight = ctx.currentBlockHeight
    val channelId: ByteVector32 by lazy {
        when (state) {
            is ChannelStateWithCommitments -> state.channelId
            is WaitForFundingCreated -> state.channelId
            is WaitForFundingSigned -> state.channelId
            else -> error("no channel id in state ${state::class}")
        }
    }
    val commitments: Commitments by lazy {
        when {
            state is ChannelStateWithCommitments -> state.commitments
            state is Offline && state.state is ChannelStateWithCommitments -> (state.state as ChannelStateWithCommitments).commitments
            state is Syncing && state.state is ChannelStateWithCommitments -> (state.state as ChannelStateWithCommitments).commitments
            else -> error("no commitments in state ${state::class}")
        }
    }

    fun process(cmd: ChannelCommand): Pair<LNChannel<ChannelState>, List<ChannelAction>> = runBlocking {
        state
            .run { ctx.copy(logger = ctx.logger.copy(staticMdc = state.mdc())).process(cmd) }
            .let { (newState, actions) ->
                checkSerialization(actions)
                JsonSerializers.json.encodeToString(newState)
                LNChannel(ctx, newState) to actions
            }
    }

    /** same as [process] but with the added assumption that we stay in the same state */
    fun processSameState(event: ChannelCommand): Pair<LNChannel<S>, List<ChannelAction>> {
        val (newState, actions) = this.process(event)
        assertIs<LNChannel<S>>(newState)
        return newState to actions
    }

    // we check that serialization works by checking that deserialize(serialize(state)) == state
    private fun checkSerialization(state: PersistedChannelState) {

        // We don't persist unsigned funding RBF or splice attempts.
        fun removeTemporaryStatuses(state: PersistedChannelState): PersistedChannelState = when (state) {
            is WaitForFundingConfirmed -> when (state.rbfStatus) {
                is RbfStatus.WaitingForSigs -> state
                else -> state.copy(rbfStatus = RbfStatus.None)
            }
            is Normal -> when (state.spliceStatus) {
                is SpliceStatus.WaitingForSigs -> state
                else -> state.copy(spliceStatus = SpliceStatus.None)
            }
            else -> state
        }

        val serialized = Serialization.serialize(state)
        val deserialized = Serialization.deserialize(serialized).value

        assertEquals(removeTemporaryStatuses(state), deserialized, "serialization error")
    }

    private fun checkSerialization(actions: List<ChannelAction>) {
        // we check that serialization works everytime we're supposed to persist channel data
        actions.filterIsInstance<ChannelAction.Storage.StoreState>().forEach { checkSerialization(it.data) }
    }

}

object TestsHelper {

    fun init(
        channelType: ChannelType.SupportedChannelType = ChannelType.SupportedChannelType.AnchorOutputs,
        aliceFeatures: Features = TestConstants.Alice.nodeParams.features,
        bobFeatures: Features = TestConstants.Bob.nodeParams.features,
        currentHeight: Int = TestConstants.defaultBlockHeight,
        aliceFundingAmount: Satoshi = TestConstants.aliceFundingAmount,
        bobFundingAmount: Satoshi = TestConstants.bobFundingAmount,
        requestRemoteFunding: Satoshi? = null,
        zeroConf: Boolean = false,
        channelOrigin: Origin? = null
    ): Triple<LNChannel<WaitForAcceptChannel>, LNChannel<WaitForOpenChannel>, OpenDualFundedChannel> {
        val (aliceNodeParams, bobNodeParams) = when (zeroConf) {
            true -> Pair(
                TestConstants.Alice.nodeParams.copy(features = aliceFeatures, zeroConfPeers = setOf(TestConstants.Bob.nodeParams.nodeId)),
                TestConstants.Bob.nodeParams.copy(features = bobFeatures, zeroConfPeers = setOf(TestConstants.Alice.nodeParams.nodeId))
            )
            false -> Pair(
                TestConstants.Alice.nodeParams.copy(features = aliceFeatures),
                TestConstants.Bob.nodeParams.copy(features = bobFeatures)
            )
        }
        val alice = LNChannel(
            ChannelContext(
                StaticParams(aliceNodeParams, TestConstants.Bob.nodeParams.nodeId),
                currentBlockHeight = currentHeight,
                onChainFeerates = MutableStateFlow(OnChainFeerates(TestConstants.feeratePerKw, TestConstants.feeratePerKw, TestConstants.feeratePerKw, TestConstants.feeratePerKw)),
                logger = MDCLogger(testLoggerFactory.newLogger("ChannelState"))
            ),
            WaitForInit
        )
        val bob = LNChannel(
            ChannelContext(
                StaticParams(bobNodeParams, TestConstants.Alice.nodeParams.nodeId),
                currentBlockHeight = currentHeight,
                onChainFeerates = MutableStateFlow(OnChainFeerates(TestConstants.feeratePerKw, TestConstants.feeratePerKw, TestConstants.feeratePerKw, TestConstants.feeratePerKw)),
                logger = MDCLogger(testLoggerFactory.newLogger("ChannelState"))
            ),
            WaitForInit
        )

        val channelFlags = ChannelFlags(announceChannel = false, nonInitiatorPaysCommitFees = requestRemoteFunding != null)
        val aliceChannelParams = TestConstants.Alice.channelParams(payCommitTxFees = !channelFlags.nonInitiatorPaysCommitFees).copy(features = aliceFeatures.initFeatures())
        val bobChannelParams = TestConstants.Bob.channelParams(payCommitTxFees = channelFlags.nonInitiatorPaysCommitFees).copy(features = bobFeatures.initFeatures())
        val aliceInit = Init(aliceFeatures)
        val bobInit = Init(bobFeatures)
        val (alice1, actionsAlice1) = alice.process(
            ChannelCommand.Init.Initiator(
                CompletableDeferred(),
                aliceFundingAmount,
                createWallet(aliceNodeParams.keyManager, aliceFundingAmount + 3500.sat).second,
                FeeratePerKw.CommitmentFeerate,
                TestConstants.feeratePerKw,
                aliceChannelParams,
                bobInit,
                channelFlags,
                ChannelConfig.standard,
                channelType,
                requestRemoteFunding?.let {
                    when (channelOrigin) {
                        is Origin.OffChainPayment -> LiquidityAds.RequestFunding(it, TestConstants.fundingRates.findRate(it)!!, LiquidityAds.PaymentDetails.FromFutureHtlc(listOf(channelOrigin.paymentHash)))
                        else -> LiquidityAds.RequestFunding(it, TestConstants.fundingRates.findRate(it)!!, LiquidityAds.PaymentDetails.FromChannelBalance)
                    }
                },
                channelOrigin,
            )
        )
        assertIs<LNChannel<WaitForAcceptChannel>>(alice1)
        val temporaryChannelId = aliceChannelParams.channelKeys(alice.ctx.keyManager).temporaryChannelId
        val bobWallet = if (bobFundingAmount > 0.sat) createWallet(bobNodeParams.keyManager, bobFundingAmount + 1500.sat).second else listOf()
        val (bob1, _) = bob.process(
            ChannelCommand.Init.NonInitiator(
                CompletableDeferred(),
                temporaryChannelId,
                bobFundingAmount,
                bobWallet,
                bobChannelParams,
                ChannelConfig.standard,
                aliceInit,
                TestConstants.fundingRates
            )
        )
        assertIs<LNChannel<WaitForOpenChannel>>(bob1)
        val open = actionsAlice1.findOutgoingMessage<OpenDualFundedChannel>()
        return Triple(alice1, bob1, open)
    }

    fun reachNormal(
        channelType: ChannelType.SupportedChannelType = ChannelType.SupportedChannelType.AnchorOutputs,
        aliceFeatures: Features = TestConstants.Alice.nodeParams.features.initFeatures(),
        bobFeatures: Features = TestConstants.Bob.nodeParams.features.initFeatures(),
        currentHeight: Int = TestConstants.defaultBlockHeight,
        aliceFundingAmount: Satoshi = TestConstants.aliceFundingAmount,
        bobFundingAmount: Satoshi = TestConstants.bobFundingAmount,
        requestRemoteFunding: Satoshi? = null,
        zeroConf: Boolean = false,
    ): Triple<LNChannel<Normal>, LNChannel<Normal>, Transaction> {
        val (alice, channelReadyAlice, bob, channelReadyBob) = WaitForChannelReadyTestsCommon.init(
            channelType,
            aliceFeatures,
            bobFeatures,
            currentHeight,
            aliceFundingAmount,
            bobFundingAmount,
            requestRemoteFunding,
            zeroConf
        )
        val (alice1, actionsAlice1) = alice.process(ChannelCommand.MessageReceived(channelReadyBob))
        assertIs<LNChannel<Normal>>(alice1)
        actionsAlice1.has<ChannelAction.Storage.StoreState>()
        val (bob1, actionsBob1) = bob.process(ChannelCommand.MessageReceived(channelReadyAlice))
        assertIs<LNChannel<Normal>>(bob1)
        actionsBob1.has<ChannelAction.Storage.StoreState>()
        val fundingTx = when (val fundingStatus = alice.commitments.latest.localFundingStatus) {
            is LocalFundingStatus.UnconfirmedFundingTx -> fundingStatus.sharedTx.tx.buildUnsignedTx()
            is LocalFundingStatus.ConfirmedFundingTx -> fundingStatus.signedTx
        }
        return Triple(alice1, bob1, fundingTx)
    }

    fun mutualCloseAlice(alice: LNChannel<Normal>, bob: LNChannel<Normal>, scriptPubKey: ByteVector? = null, feerates: ClosingFeerates? = null): Triple<LNChannel<Negotiating>, LNChannel<Negotiating>, ClosingSigned> {
        val (alice1, actionsAlice1) = alice.process(ChannelCommand.Close.MutualClose(scriptPubKey, feerates))
        assertIs<LNChannel<Normal>>(alice1)
        val shutdownAlice = actionsAlice1.findOutgoingMessage<Shutdown>()
        assertNull(actionsAlice1.findOutgoingMessageOpt<ClosingSigned>())

        val (bob1, actionsBob1) = bob.process(ChannelCommand.MessageReceived(shutdownAlice))
        assertIs<LNChannel<Negotiating>>(bob1)
        val shutdownBob = actionsBob1.findOutgoingMessage<Shutdown>()
        assertNull(actionsBob1.findOutgoingMessageOpt<ClosingSigned>())

        val (alice2, actionsAlice2) = alice1.process(ChannelCommand.MessageReceived(shutdownBob))
        assertIs<LNChannel<Negotiating>>(alice2)
        val closingSignedAlice = actionsAlice2.findOutgoingMessage<ClosingSigned>()
        return Triple(alice2, bob1, closingSignedAlice)
    }

    fun mutualCloseBob(alice: LNChannel<Normal>, bob: LNChannel<Normal>, scriptPubKey: ByteVector? = null, feerates: ClosingFeerates? = null): Triple<LNChannel<Negotiating>, LNChannel<Negotiating>, ClosingSigned> {
        val (bob1, actionsBob1) = bob.process(ChannelCommand.Close.MutualClose(scriptPubKey, feerates))
        assertIs<LNChannel<Normal>>(bob1)
        val shutdownBob = actionsBob1.findOutgoingMessage<Shutdown>()
        assertNull(actionsBob1.findOutgoingMessageOpt<ClosingSigned>())

        val (alice1, actionsAlice1) = alice.process(ChannelCommand.MessageReceived(shutdownBob))
        assertIs<LNChannel<Negotiating>>(alice1)
        val shutdownAlice = actionsAlice1.findOutgoingMessage<Shutdown>()
        val closingSignedAlice = actionsAlice1.findOutgoingMessage<ClosingSigned>()

        val (bob2, actionsBob2) = bob1.process(ChannelCommand.MessageReceived(shutdownAlice))
        assertIs<LNChannel<Negotiating>>(bob2)
        assertNull(actionsBob2.findOutgoingMessageOpt<ClosingSigned>())
        return Triple(alice1, bob2, closingSignedAlice)
    }

    fun localClose(s: LNChannel<ChannelState>): Pair<LNChannel<Closing>, LocalCommitPublished> {
        assertIs<LNChannel<ChannelStateWithCommitments>>(s)
        assertContains(s.state.commitments.params.channelFeatures.features, Feature.AnchorOutputs)
        // an error occurs and s publishes their commit tx
        val commitTx = s.state.commitments.latest.localCommit.publishableTxs.commitTx.tx
        val (s1, actions1) = s.process(ChannelCommand.MessageReceived(Error(ByteVector32.Zeroes, "oops")))
        assertIs<LNChannel<Closing>>(s1)
        actions1.has<ChannelAction.Storage.StoreState>()
        actions1.find<ChannelAction.Storage.StoreOutgoingPayment.ViaClose>().also {
            assertEquals(commitTx.txid, it.txId)
            assertEquals(ChannelCloseOutgoingPayment.ChannelClosingType.Local, it.closingType)
        }

        val localCommitPublished = s1.state.localCommitPublished
        assertNotNull(localCommitPublished)
        assertEquals(commitTx, localCommitPublished.commitTx)
        actions1.hasPublishTx(commitTx)
        assertNotNull(localCommitPublished.claimMainDelayedOutputTx)
        actions1.hasPublishTx(localCommitPublished.claimMainDelayedOutputTx!!.tx)
        Transaction.correctlySpends(localCommitPublished.claimMainDelayedOutputTx!!.tx, localCommitPublished.commitTx, ScriptFlags.STANDARD_SCRIPT_VERIFY_FLAGS)
        // all htlcs success/timeout should be published
        localCommitPublished.htlcTxs.values.filterNotNull().forEach { htlcTx ->
            Transaction.correctlySpends(htlcTx.tx, localCommitPublished.commitTx, ScriptFlags.STANDARD_SCRIPT_VERIFY_FLAGS)
            actions1.hasPublishTx(htlcTx.tx)
        }
        // and their outputs should be claimed
        localCommitPublished.claimHtlcDelayedTxs.forEach { claimHtlcDelayed -> actions1.hasPublishTx(claimHtlcDelayed.tx) }

        // we watch the confirmation of the "final" transactions that send funds to our wallets (main delayed output and 2nd stage htlc transactions)
        val expectedWatchConfirmed = buildSet {
            add(BITCOIN_TX_CONFIRMED(localCommitPublished.commitTx))
            add(BITCOIN_TX_CONFIRMED(localCommitPublished.claimMainDelayedOutputTx!!.tx))
            addAll(localCommitPublished.claimHtlcDelayedTxs.map { BITCOIN_TX_CONFIRMED(it.tx) })
        }
        assertEquals(expectedWatchConfirmed, actions1.findWatches<WatchConfirmed>().map { it.event }.toSet())

        // we watch outputs of the commitment tx that both parties may spend
        val watchSpent = actions1.findWatches<WatchSpent>()
        watchSpent.forEach { watch ->
            assertEquals(BITCOIN_OUTPUT_SPENT, watch.event)
            assertEquals(watch.txId, commitTx.txid)
        }
        assertEquals(localCommitPublished.htlcTxs.keys, watchSpent.map { OutPoint(commitTx, it.outputIndex.toLong()) }.toSet())

        return s1 to localCommitPublished
    }

    fun remoteClose(rCommitTx: Transaction, s: LNChannel<ChannelState>): Pair<LNChannel<Closing>, RemoteCommitPublished> {
        assertIs<LNChannel<ChannelStateWithCommitments>>(s)
        assertContains(s.state.commitments.params.channelFeatures.features, Feature.AnchorOutputs)
        // we make s believe r unilaterally closed the channel
        val (s1, actions1) = s.process(ChannelCommand.WatchReceived(WatchEventSpent(s.state.channelId, BITCOIN_FUNDING_SPENT, rCommitTx)))
        assertIs<LNChannel<Closing>>(s1)

        if (s.state !is Closing) {
            val channelBalance = s.state.commitments.latest.localCommit.spec.toLocal
            if (channelBalance > 0.msat) {
                actions1.find<ChannelAction.Storage.StoreOutgoingPayment.ViaClose>().also {
                    assertEquals(rCommitTx.txid, it.txId)
                    assertEquals(ChannelClosingType.Remote, it.closingType)
                }
            }
        }

        val remoteCommitPublished = s1.state.remoteCommitPublished ?: s1.state.nextRemoteCommitPublished ?: s1.state.futureRemoteCommitPublished
        assertNotNull(remoteCommitPublished)
        assertNull(s1.state.localCommitPublished)

        // if s has a main output in the commit tx (when it has a non-dust balance), it should be claimed
        remoteCommitPublished.claimMainOutputTx?.let { claimMain ->
            Transaction.correctlySpends(claimMain.tx, rCommitTx, ScriptFlags.STANDARD_SCRIPT_VERIFY_FLAGS)
            actions1.hasPublishTx(claimMain.tx)
        }
        // all htlcs success/timeout should be claimed
        remoteCommitPublished.claimHtlcTxs.values.filterNotNull().forEach { claimHtlc ->
            Transaction.correctlySpends(claimHtlc.tx, rCommitTx, ScriptFlags.STANDARD_SCRIPT_VERIFY_FLAGS)
            actions1.hasPublishTx(claimHtlc.tx)
        }

        // we watch the confirmation of the "final" transactions that send funds to our wallets (main delayed output and 2nd stage htlc transactions)
        val watchConfirmedList = actions1.findWatches<WatchConfirmed>()
        assertEquals(BITCOIN_TX_CONFIRMED(rCommitTx), watchConfirmedList.first().event)
        remoteCommitPublished.claimMainOutputTx?.let { claimMain ->
            assertEquals(BITCOIN_TX_CONFIRMED(claimMain.tx), watchConfirmedList.drop(1).first().event)
        }

        // we watch outputs of the commitment tx that both parties may spend
        val watchSpent = actions1.findWatches<WatchSpent>()
        watchSpent.forEach { watch ->
            assertEquals(BITCOIN_OUTPUT_SPENT, watch.event)
            assertEquals(watch.txId, rCommitTx.txid)
        }
        assertEquals(remoteCommitPublished.claimHtlcTxs.keys, watchSpent.map { OutPoint(rCommitTx, it.outputIndex.toLong()) }.toSet())

        // s is now in CLOSING state with txs pending for confirmation before going in CLOSED state
        return s1 to remoteCommitPublished
    }

    fun useAlternativeCommitSig(s: LNChannel<ChannelState>, commitment: Commitment, alternative: CommitSigTlv.AlternativeFeerateSig): Transaction {
        val channelKeys = s.commitments.params.localParams.channelKeys(s.ctx.keyManager)
        val alternativeSpec = commitment.localCommit.spec.copy(feerate = alternative.feerate)
        val fundingTxIndex = commitment.fundingTxIndex
        val commitInput = commitment.commitInput
        val remoteFundingPubKey = commitment.remoteFundingPubkey
        val localPerCommitmentPoint = channelKeys.commitmentPoint(commitment.localCommit.index)
        val (localCommitTx, _) = Commitments.makeLocalTxs(
            channelKeys,
            commitment.localCommit.index,
            s.commitments.params.localParams,
            s.commitments.params.remoteParams,
            fundingTxIndex,
            remoteFundingPubKey,
            commitInput,
            localPerCommitmentPoint,
            alternativeSpec
        )
        val localSig = Transactions.sign(localCommitTx, channelKeys.fundingKey(fundingTxIndex))
        val signedCommitTx = Transactions.addSigs(localCommitTx, channelKeys.fundingPubKey(fundingTxIndex), remoteFundingPubKey, localSig, alternative.sig)
        assertTrue(Transactions.checkSpendable(signedCommitTx).isSuccess)
        return signedCommitTx.tx
    }

    fun signAndRevack(alice: LNChannel<ChannelState>, bob: LNChannel<ChannelState>): Pair<LNChannel<ChannelState>, LNChannel<ChannelState>> {
        val (alice1, actions1) = alice.process(ChannelCommand.Commitment.Sign)
        val commitSig = actions1.findOutgoingMessage<CommitSig>()
        val (bob1, actions2) = bob.process(ChannelCommand.MessageReceived(commitSig))
        val revack = actions2.findOutgoingMessage<RevokeAndAck>()
        val (alice2, _) = alice1.process(ChannelCommand.MessageReceived(revack))
        return Pair(alice2, bob1)
    }

    fun makeCmdAdd(amount: MilliSatoshi, destination: PublicKey, currentBlockHeight: Long, paymentPreimage: ByteVector32 = randomBytes32(), paymentId: UUID = UUID.randomUUID()): Pair<ByteVector32, ChannelCommand.Htlc.Add> {
        val paymentHash = Crypto.sha256(paymentPreimage).toByteVector32()
        val expiry = CltvExpiryDelta(144).toCltvExpiry(currentBlockHeight)
        val payload = PaymentOnion.FinalPayload.Standard.createSinglePartPayload(amount, expiry, randomBytes32(), null)
        val onion = OutgoingPaymentPacket.buildOnion(listOf(destination), listOf(payload), paymentHash, OnionRoutingPacket.PaymentPacketLength).packet
        val cmd = ChannelCommand.Htlc.Add(amount, paymentHash, expiry, onion, paymentId, commit = false)
        return Pair(paymentPreimage, cmd)
    }

    fun createWallet(keyManager: KeyManager, amount: Satoshi): Pair<PrivateKey, List<WalletState.Utxo>> {
        val swapInAddressIndex = 0
        val (privateKey, script) = keyManager.swapInOnChainWallet.run { Pair(userPrivateKey, getSwapInProtocol(swapInAddressIndex).pubkeyScript) }
        val parentTx = Transaction(2, listOf(TxIn(OutPoint(TxId(randomBytes32()), 3), 0)), listOf(TxOut(amount, script)), 0)
        return privateKey to listOf(WalletState.Utxo(parentTx.txid, 0, 42, parentTx, WalletState.AddressMeta.Derived(swapInAddressIndex)))
    }

    fun <T : ChannelState> addHtlc(amount: MilliSatoshi, payer: LNChannel<T>, payee: LNChannel<T>): Triple<Pair<LNChannel<T>, LNChannel<T>>, ByteVector32, UpdateAddHtlc> {
        val currentBlockHeight = payer.currentBlockHeight.toLong()
        val (paymentPreimage, cmd) = makeCmdAdd(amount, payee.staticParams.nodeParams.nodeId, currentBlockHeight)
        val (sender0, receiver0, htlc) = addHtlc(cmd, payer, payee)
        return Triple(sender0 to receiver0, paymentPreimage, htlc)
    }

    fun <T : ChannelState> addHtlc(cmdAdd: ChannelCommand.Htlc.Add, payer: LNChannel<T>, payee: LNChannel<T>): Triple<LNChannel<T>, LNChannel<T>, UpdateAddHtlc> {
        val (sender0, senderActions0) = payer.process(cmdAdd)
        val htlc = senderActions0.findOutgoingMessage<UpdateAddHtlc>()

        val (receiver0, _) = payee.process(ChannelCommand.MessageReceived(htlc))
        assertIs<LNChannel<ChannelStateWithCommitments>>(receiver0)
        assertTrue(receiver0.state.commitments.changes.remoteChanges.proposed.contains(htlc))

        assertIs<LNChannel<T>>(sender0)
        assertIs<LNChannel<T>>(receiver0)
        return Triple(sender0, receiver0, htlc)
    }

    fun <T : ChannelState> fulfillHtlc(id: Long, paymentPreimage: ByteVector32, payer: LNChannel<T>, payee: LNChannel<T>): Pair<LNChannel<T>, LNChannel<T>> {
        val (payee0, payeeActions0) = payee.process(ChannelCommand.Htlc.Settlement.Fulfill(id, paymentPreimage))
        val fulfillHtlc = payeeActions0.findOutgoingMessage<UpdateFulfillHtlc>()

        val (payer0, _) = payer.process(ChannelCommand.MessageReceived(fulfillHtlc))
        assertIs<LNChannel<ChannelStateWithCommitments>>(payer0)
        assertTrue(payer0.state.commitments.changes.remoteChanges.proposed.contains(fulfillHtlc))

        assertIs<LNChannel<T>>(payer0)
        assertIs<LNChannel<T>>(payee0)
        return payer0 to payee0
    }

    fun <T : ChannelState> failHtlc(id: Long, payer: LNChannel<T>, payee: LNChannel<T>): Pair<LNChannel<T>, LNChannel<T>> {
        val (payee0, payeeActions0) = payee.process(ChannelCommand.Htlc.Settlement.Fail(id, ChannelCommand.Htlc.Settlement.Fail.Reason.Failure(TemporaryNodeFailure)))
        val failHtlc = payeeActions0.findOutgoingMessage<UpdateFailHtlc>()

        val (payer0, _) = payer.process(ChannelCommand.MessageReceived(failHtlc))
        assertIs<LNChannel<ChannelStateWithCommitments>>(payer0)
        assertTrue(payer0.state.commitments.changes.remoteChanges.proposed.contains(failHtlc))

        assertIs<LNChannel<T>>(payer0)
        assertIs<LNChannel<T>>(payee0)
        return payer0 to payee0
    }

    private fun <T : ChannelStateWithCommitments> receiveCommitSigs(receiver: LNChannel<T>, commitSigs: List<CommitSig>): Pair<LNChannel<T>, List<ChannelAction>> {
        return commitSigs.fold(Pair(receiver, emptyList())) { pair, commitSig ->
            val (statePrev, actionsPrev) = pair
            assertTrue(actionsPrev.isEmpty())
            val (stateNext, actionsNext) = statePrev.process(ChannelCommand.MessageReceived(commitSig))
            assertIs<LNChannel<T>>(stateNext)
            Pair(stateNext, actionsNext)
        }
    }

    /**
     * Cross sign nodes where nodeA initiate the signature exchange
     */
    fun <T : ChannelStateWithCommitments> crossSign(nodeA: LNChannel<T>, nodeB: LNChannel<T>, commitmentsCount: Int = 1): Pair<LNChannel<T>, LNChannel<T>> {
        val sCommitIndex = nodeA.state.commitments.localCommitIndex
        val rCommitIndex = nodeB.state.commitments.localCommitIndex
        val rHasChanges = nodeB.state.commitments.changes.localHasChanges()

        val (sender0, sActions0) = nodeA.process(ChannelCommand.Commitment.Sign)
        val commitSigs0 = sActions0.findOutgoingMessages<CommitSig>()
        assertEquals(commitmentsCount, commitSigs0.size)
        commitSigs0.forEach { assertEquals(commitmentsCount, it.batchSize) }

        val (receiver0, rActions0) = receiveCommitSigs(nodeB, commitSigs0)
        val revokeAndAck0 = rActions0.findOutgoingMessage<RevokeAndAck>()
        val commandSign0 = rActions0.findCommand<ChannelCommand.Commitment.Sign>()

        val (sender1, _) = sender0.process(ChannelCommand.MessageReceived(revokeAndAck0))
        assertIs<LNChannel<T>>(sender1)
        val (receiver1, rActions1) = receiver0.process(commandSign0)
        val commitSigs1 = rActions1.findOutgoingMessages<CommitSig>()
        assertEquals(commitmentsCount, commitSigs1.size)
        commitSigs1.forEach { assertEquals(commitmentsCount, it.batchSize) }

        val (sender2, sActions2) = receiveCommitSigs(sender1, commitSigs1)
        val revokeAndAck1 = sActions2.findOutgoingMessage<RevokeAndAck>()
        val (receiver2, _) = receiver1.process(ChannelCommand.MessageReceived(revokeAndAck1))
        assertIs<LNChannel<T>>(receiver2)

        if (rHasChanges) {
            val commandSign1 = sActions2.findCommand<ChannelCommand.Commitment.Sign>()
            val (sender3, sActions3) = sender2.process(commandSign1)
            val commitSigs2 = sActions3.findOutgoingMessages<CommitSig>()
            assertEquals(commitmentsCount, commitSigs2.size)

            val (receiver3, rActions3) = receiveCommitSigs(receiver2, commitSigs2)
            val revokeAndAck2 = rActions3.findOutgoingMessage<RevokeAndAck>()
            val (sender4, _) = sender3.process(ChannelCommand.MessageReceived(revokeAndAck2))

            assertIs<LNChannel<T>>(sender4)
            assertIs<LNChannel<T>>(receiver3)
            assertEquals(sCommitIndex + 1, sender4.commitments.localCommitIndex)
            assertEquals(rCommitIndex + 2, sender4.commitments.remoteCommitIndex)
            assertEquals(rCommitIndex + 2, receiver3.commitments.localCommitIndex)
            assertEquals(sCommitIndex + 1, receiver3.commitments.remoteCommitIndex)

            return sender4 to receiver3
        } else {
            assertIs<LNChannel<T>>(sender2)
            assertEquals(sCommitIndex + 1, sender2.commitments.localCommitIndex)
            assertEquals(rCommitIndex + 1, sender2.commitments.remoteCommitIndex)
            assertEquals(rCommitIndex + 1, receiver2.commitments.localCommitIndex)
            assertEquals(sCommitIndex + 1, receiver2.commitments.remoteCommitIndex)

            return sender2 to receiver2
        }
    }

    fun LocalCommitPublished.htlcSuccessTxs(): List<Transactions.TransactionWithInputInfo.HtlcTx.HtlcSuccessTx> {
        return htlcTxs.values.filterIsInstance<Transactions.TransactionWithInputInfo.HtlcTx.HtlcSuccessTx>()
    }

    fun LocalCommitPublished.htlcTimeoutTxs(): List<Transactions.TransactionWithInputInfo.HtlcTx.HtlcTimeoutTx> {
        return htlcTxs.values.filterIsInstance<Transactions.TransactionWithInputInfo.HtlcTx.HtlcTimeoutTx>()
    }

    fun RemoteCommitPublished.claimHtlcSuccessTxs(): List<Transactions.TransactionWithInputInfo.ClaimHtlcTx.ClaimHtlcSuccessTx> {
        return claimHtlcTxs.values.filterIsInstance<Transactions.TransactionWithInputInfo.ClaimHtlcTx.ClaimHtlcSuccessTx>()
    }

    fun RemoteCommitPublished.claimHtlcTimeoutTxs(): List<Transactions.TransactionWithInputInfo.ClaimHtlcTx.ClaimHtlcTimeoutTx> {
        return claimHtlcTxs.values.filterIsInstance<Transactions.TransactionWithInputInfo.ClaimHtlcTx.ClaimHtlcTimeoutTx>()
    }

}
