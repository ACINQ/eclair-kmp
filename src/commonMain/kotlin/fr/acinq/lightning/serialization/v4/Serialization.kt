package fr.acinq.lightning.serialization.v4

import fr.acinq.bitcoin.*
import fr.acinq.bitcoin.io.ByteArrayOutput
import fr.acinq.bitcoin.io.Output
import fr.acinq.lightning.FeatureSupport
import fr.acinq.lightning.Features
import fr.acinq.lightning.channel.*
import fr.acinq.lightning.serialization.v4.Serialization.write
import fr.acinq.lightning.transactions.CommitmentSpec
import fr.acinq.lightning.transactions.IncomingHtlc
import fr.acinq.lightning.transactions.OutgoingHtlc
import fr.acinq.lightning.transactions.Transactions
import fr.acinq.lightning.transactions.Transactions.TransactionWithInputInfo.*
import fr.acinq.lightning.utils.Either
import fr.acinq.lightning.wire.LightningCodecs
import fr.acinq.lightning.wire.LightningMessage

/**
 * Serialization for [ChannelStateWithCommitments].
 *
 * This is a large file, but it's just repetition of the same pattern
 *
 * We define extension methods on the class [Output] to serialize various types
 * from primitives to structures:
 * ```
 *  private fun Output.write(o: MyType): Unit
 * ```
 *
 * Then we just iterate over all fields of the top level class we want to serialize, and call the
 * [write] method on all of them.
 *
 * We defer serialization of Bitcoin and Lightning protocol messages to the respective [BtcSerializer]
 * and [LightningCodecs].
 */
object Serialization {

    const val versionMagic = 4

    fun serialize(o: PersistedChannelState): ByteArray {
        val out = ByteArrayOutput()
        out.write(versionMagic)
        out.writePersistedChannelState(o)
        return out.toByteArray()
    }

    private fun Output.writePersistedChannelState(o: PersistedChannelState) = when (o) {
        is LegacyWaitForFundingConfirmed -> {
            write(0x08); writeLegacyWaitForFundingConfirmed(o)
        }
        is LegacyWaitForFundingLocked -> {
            write(0x09); writeLegacyWaitForFundingLocked(o)
        }
        is WaitForFundingConfirmed -> {
            write(0x00); writeWaitForFundingConfirmed(o)
        }
        is WaitForChannelReady -> {
            write(0x01); writeWaitForChannelReady(o)
        }
        is Normal -> {
            write(0x02); writeNormal(o)
        }
        is ShuttingDown -> {
            write(0x03); writeShuttingDown(o)
        }
        is Negotiating -> {
            write(0x04); writeNegotiating(o)
        }
        is Closing -> {
            write(0x05); writeClosing(o)
        }
        is WaitForRemotePublishFutureCommitment -> {
            write(0x06); writeWaitForRemotePublishFutureCommitment(o)
        }
        is Closed -> {
            write(0x07); writeClosed(o)
        }
    }

    private fun Output.writeLegacyWaitForFundingConfirmed(o: LegacyWaitForFundingConfirmed) = o.run {
        writeCommitments(commitments)
        writeNullable(fundingTx) { writeBtcObject(it) }
        writeNumber(waitingSinceBlock)
        writeNullable(deferred) { writeLightningMessage(it) }
        writeEither(lastSent,
            writeLeft = { writeLightningMessage(it) },
            writeRight = { writeLightningMessage(it) }
        )
    }

    private fun Output.writeLegacyWaitForFundingLocked(o: LegacyWaitForFundingLocked) = o.run {
        writeCommitments(commitments)
        writeNumber(shortChannelId.toLong())
        writeLightningMessage(lastSent)
    }

    private fun Output.writeWaitForFundingConfirmed(o: WaitForFundingConfirmed) = o.run {
        writeCommitments(commitments)
        writeNumber(localPushAmount.toLong())
        writeNumber(remotePushAmount.toLong())
        writeNumber(waitingSinceBlock)
        writeNullable(deferred) { writeLightningMessage(it) }
    }

    private fun Output.writeWaitForChannelReady(o: WaitForChannelReady) = o.run {
        writeCommitments(commitments)
        writeNumber(shortChannelId.toLong())
        writeLightningMessage(lastSent)
    }

    private fun Output.writeNormal(o: Normal) = o.run {
        writeCommitments(commitments)
        writeNumber(shortChannelId.toLong())
        writeBoolean(buried)
        writeNullable(channelAnnouncement) { writeLightningMessage(it) }
        writeLightningMessage(channelUpdate)
        writeNullable(remoteChannelUpdate) { writeLightningMessage(it) }
        writeNullable(localShutdown) { writeLightningMessage(it) }
        writeNullable(remoteShutdown) { writeLightningMessage(it) }
        writeNullable(closingFeerates) { writeClosingFeerates(it) }
    }

    private fun Output.writeShuttingDown(o: ShuttingDown) = o.run {
        writeCommitments(commitments)
        writeLightningMessage(localShutdown)
        writeLightningMessage(remoteShutdown)
        writeNullable(closingFeerates) { writeClosingFeerates(it) }
    }

    private fun Output.writeNegotiating(o: Negotiating) = o.run {
        writeCommitments(commitments)
        writeLightningMessage(localShutdown)
        writeLightningMessage(remoteShutdown)
        writeCollection(closingTxProposed) {
            writeCollection(it) { closingTxProposed ->
                closingTxProposed.run {
                    writeTransactionWithInputInfo(unsignedTx)
                    writeLightningMessage(localClosingSigned)
                }
            }
        }
        writeNullable(bestUnpublishedClosingTx) { writeTransactionWithInputInfo(it) }
        writeNullable(closingFeerates) { writeClosingFeerates(it) }
    }

    private fun Output.writeClosing(o: Closing) = o.run {
        writeCommitments(commitments)
        writeNumber(waitingSinceBlock)
        writeCollection(mutualCloseProposed) { writeTransactionWithInputInfo(it) }
        writeCollection(mutualClosePublished) { writeTransactionWithInputInfo(it) }
        writeNullable(localCommitPublished) { writeLocalCommitPublished(it) }
        writeNullable(remoteCommitPublished) { writeRemoteCommitPublished(it) }
        writeNullable(nextRemoteCommitPublished) { writeRemoteCommitPublished(it) }
        writeNullable(futureRemoteCommitPublished) { writeRemoteCommitPublished(it) }
        writeCollection(revokedCommitPublished) { writeRevokedCommitPublished(it) }
    }

    private fun Output.writeLocalCommitPublished(o: LocalCommitPublished) = o.run {
        writeBtcObject(commitTx)
        writeNullable(claimMainDelayedOutputTx) { writeTransactionWithInputInfo(it) }
        writeCollection(htlcTxs.entries) {
            writeBtcObject(it.key)
            writeNullable(it.value) { htlcTx -> writeTransactionWithInputInfo(htlcTx) }
        }
        writeCollection(claimHtlcDelayedTxs) { writeTransactionWithInputInfo(it) }
        writeCollection(claimAnchorTxs) { writeTransactionWithInputInfo(it) }
        writeIrrevocablySpent(irrevocablySpent)
    }

    private fun Output.writeRemoteCommitPublished(o: RemoteCommitPublished) = o.run {
        writeBtcObject(commitTx)
        writeNullable(claimMainOutputTx) { writeTransactionWithInputInfo(it) }
        writeCollection(claimHtlcTxs.entries) {
            writeBtcObject(it.key)
            writeNullable(it.value) { claimHtlcTx -> writeTransactionWithInputInfo(claimHtlcTx) }
        }
        writeCollection(claimAnchorTxs) { writeTransactionWithInputInfo(it) }
        writeIrrevocablySpent(irrevocablySpent)
    }

    private fun Output.writeRevokedCommitPublished(o: RevokedCommitPublished) = o.run {
        writeBtcObject(commitTx)
        writeByteVector32(remotePerCommitmentSecret.value)
        writeNullable(claimMainOutputTx) { writeTransactionWithInputInfo(it) }
        writeNullable(mainPenaltyTx) { writeTransactionWithInputInfo(it) }
        writeCollection(htlcPenaltyTxs) { writeTransactionWithInputInfo(it) }
        writeCollection(claimHtlcDelayedPenaltyTxs) { writeTransactionWithInputInfo(it) }
        writeIrrevocablySpent(irrevocablySpent)
    }

    private fun Output.writeIrrevocablySpent(o: Map<OutPoint, Transaction>) = writeCollection(o.entries) {
        writeBtcObject(it.key)
        writeBtcObject(it.value)
    }

    private fun Output.writeWaitForRemotePublishFutureCommitment(o: WaitForRemotePublishFutureCommitment) = o.run {
        writeCommitments(commitments)
        writeLightningMessage(remoteChannelReestablish)
    }

    private fun Output.writeClosed(o: Closed) = o.run {
        writeClosing(state)
    }

    private fun Output.writeSharedFundingInput(i: SharedFundingInput) = when (i) {
        is SharedFundingInput.Multisig2of2 -> {
            write(0x01)
            writeInputInfo(i.info)
            writePublicKey(i.localFundingPubkey)
            writePublicKey(i.remoteFundingPubkey)
        }
    }

    private fun Output.writeInteractiveTxParams(o: InteractiveTxParams) = o.run {
        writeByteVector32(channelId)
        writeBoolean(isInitiator)
        writeNumber(localAmount.toLong())
        writeNumber(remoteAmount.toLong())
        writeNullable(sharedInput) { writeSharedFundingInput(it) }
        writeDelimited(fundingPubkeyScript.toByteArray())
        writeCollection(localOutputs) { writeBtcObject(it) }
        writeNumber(lockTime)
        writeNumber(dustLimit.toLong())
        writeNumber(targetFeerate.toLong())
    }

    private fun Output.writeSharedInteractiveTxInput(i: InteractiveTxInput.Shared) = i.run {
        writeNumber(serialId)
        writeBtcObject(outPoint)
        writeNumber(sequence.toLong())
        writeNumber(localAmount.toLong())
        writeNumber(remoteAmount.toLong())
    }

    private fun Output.writeLocalInteractiveTxInput(i: InteractiveTxInput.Local) = i.run {
        writeNumber(serialId)
        writeBtcObject(previousTx)
        writeNumber(previousTxOutput)
        writeNumber(sequence.toLong())
    }

    private fun Output.writeRemoteInteractiveTxInput(i: InteractiveTxInput.Remote) = i.run {
        writeNumber(serialId)
        writeBtcObject(outPoint)
        writeBtcObject(txOut)
        writeNumber(sequence.toLong())
    }

    private fun Output.writeSharedInteractiveTxOutput(o: InteractiveTxOutput.Shared) = o.run {
        writeNumber(serialId)
        writeDelimited(pubkeyScript.toByteArray())
        writeNumber(localAmount.toLong())
        writeNumber(remoteAmount.toLong())
    }

    private fun Output.writeLocalInteractiveTxOutput(o: InteractiveTxOutput.Local) = when (o) {
        is InteractiveTxOutput.Local.Change -> o.run {
            write(0x01)
            writeNumber(serialId)
            writeNumber(amount.toLong())
            writeDelimited(pubkeyScript.toByteArray())
        }
        is InteractiveTxOutput.Local.NonChange -> o.run {
            write(0x02)
            writeNumber(serialId)
            writeNumber(amount.toLong())
            writeDelimited(pubkeyScript.toByteArray())
        }
    }

    private fun Output.writeRemoteInteractiveTxOutput(o: InteractiveTxOutput.Remote) = o.run {
        writeNumber(serialId)
        writeNumber(amount.toLong())
        writeDelimited(pubkeyScript.toByteArray())
    }

    private fun Output.writeSharedTransaction(tx: SharedTransaction) = tx.run {
        writeNullable(sharedInput) { writeSharedInteractiveTxInput(it) }
        writeSharedInteractiveTxOutput(sharedOutput)
        writeCollection(localInputs) { writeLocalInteractiveTxInput(it) }
        writeCollection(remoteInputs) { writeRemoteInteractiveTxInput(it) }
        writeCollection(localOutputs) { writeLocalInteractiveTxOutput(it) }
        writeCollection(remoteOutputs) { writeRemoteInteractiveTxOutput(it) }
        writeNumber(lockTime)
    }

    private fun Output.writeScriptWitness(w: ScriptWitness) = writeCollection(w.stack) { writeDelimited(it.toByteArray()) }

    private fun Output.writeSignedSharedTransaction(o: SignedSharedTransaction) = when (o) {
        is PartiallySignedSharedTransaction -> o.run {
            write(0x01)
            writeSharedTransaction(tx)
            writeLightningMessage(localSigs)
        }
        is FullySignedSharedTransaction -> o.run {
            write(0x02)
            writeSharedTransaction(tx)
            writeLightningMessage(localSigs)
            writeLightningMessage(remoteSigs)
            writeNullable(sharedSigs) { writeScriptWitness(it) }
        }
    }

    private fun Output.writeChannelParams(o: ChannelParams) = o.run {
        writeByteVector32(channelId)
        writeDelimited(channelConfig.toByteArray())
        writeDelimited(Features(channelFeatures.features.associateWith { FeatureSupport.Mandatory }).toByteArray())
        localParams.run {
            writePublicKey(nodeId)
            writeCollection(fundingKeyPath.path) { writeNumber(it) }
            writeNumber(dustLimit.toLong())
            writeNumber(maxHtlcValueInFlightMsat)
            writeNumber(htlcMinimum.toLong())
            writeNumber(toSelfDelay.toLong())
            writeNumber(maxAcceptedHtlcs)
            writeBoolean(isInitiator)
            writeDelimited(defaultFinalScriptPubKey.toByteArray())
            writeDelimited(features.toByteArray())
        }
        remoteParams.run {
            writePublicKey(nodeId)
            writeNumber(dustLimit.toLong())
            writeNumber(maxHtlcValueInFlightMsat)
            writeNumber(htlcMinimum.toLong())
            writeNumber(toSelfDelay.toLong())
            writeNumber(maxAcceptedHtlcs)
            writePublicKey(fundingPubKey)
            writePublicKey(revocationBasepoint)
            writePublicKey(paymentBasepoint)
            writePublicKey(delayedPaymentBasepoint)
            writePublicKey(htlcBasepoint)
            writeDelimited(features.toByteArray())
        }
        writeNumber(channelFlags)
    }

    private fun Output.writeCommitmentChanges(o: CommitmentChanges) = o.run {
        localChanges.run {
            writeCollection(proposed) { writeLightningMessage(it) }
            writeCollection(signed) { writeLightningMessage(it) }
            writeCollection(acked) { writeLightningMessage(it) }
        }
        remoteChanges.run {
            writeCollection(proposed) { writeLightningMessage(it) }
            writeCollection(acked) { writeLightningMessage(it) }
            writeCollection(signed) { writeLightningMessage(it) }
        }
        writeNumber(localNextHtlcId)
        writeNumber(remoteNextHtlcId)
    }

    private fun Output.writeCommitment(o: Commitment) = o.run {
        when (localFundingStatus) {
            is LocalFundingStatus.UnconfirmedFundingTx -> {
                write(0x00)
                writeSignedSharedTransaction(localFundingStatus.sharedTx)
                writeInteractiveTxParams(localFundingStatus.fundingParams)
                writeNumber(localFundingStatus.createdAt)
            }
            is LocalFundingStatus.ConfirmedFundingTx -> {
                write(0x01)
                writeBtcObject(localFundingStatus.signedTx)
            }
        }
        when (remoteFundingStatus) {
            is RemoteFundingStatus.NotLocked -> write(0x00)
            is RemoteFundingStatus.Locked -> write(0x01)
        }
        localCommit.run {
            writeNumber(index)
            write(spec)
            publishableTxs.run {
                writeTransactionWithInputInfo(commitTx)
                writeCollection(htlcTxsAndSigs) { htlc ->
                    writeTransactionWithInputInfo(htlc.txinfo)
                    writeByteVector64(htlc.localSig)
                    writeByteVector64(htlc.remoteSig)
                }
            }
        }
        remoteCommit.run {
            writeNumber(index)
            write(spec)
            writeByteVector32(txid)
            writePublicKey(remotePerCommitmentPoint)
        }
        writeNullable(nextRemoteCommit) {
            writeLightningMessage(it.sig)
            writeNumber(it.commit.index)
            write(it.commit.spec)
            writeByteVector32(it.commit.txid)
            writePublicKey(it.commit.remotePerCommitmentPoint)
        }
    }

    private fun Output.writeCommitments(o: Commitments) = o.run {
        writeChannelParams(params)
        writeCommitmentChanges(changes)
        writeCollection(active) { writeCommitment(it) }
        writeCollection(payments.entries) { entry ->
            writeNumber(entry.key)
            writeString(entry.value.toString())
        }
        writeEither(remoteNextCommitInfo,
            writeLeft = { writeNumber(it.sentAfterLocalCommitIndex) },
            writeRight = { writePublicKey(it) }
        )
        remotePerCommitmentSecrets.run {
            writeCollection(knownHashes.entries) { entry ->
                writeCollection(entry.key) { writeBoolean(it) }
                writeByteVector32(entry.value)
            }
            writeNullable(lastIndex) { writeNumber(it) }
        }
        writeDelimited(remoteChannelData.data.toByteArray())
    }

    private fun Output.write(o: CommitmentSpec): Unit = o.run {
        writeCollection(htlcs) {
            when (it) {
                is IncomingHtlc -> write(0)
                is OutgoingHtlc -> write(1)
            }
            writeLightningMessage(it.add)
        }
        writeNumber(feerate.toLong())
        writeNumber(toLocal.toLong())
        writeNumber(toRemote.toLong())
    }

    private fun Output.writeInputInfo(o: Transactions.InputInfo): Unit = o.run {
        writeBtcObject(outPoint)
        writeBtcObject(txOut)
        writeDelimited(redeemScript.toByteArray())
    }

    private fun Output.writeTransactionWithInputInfo(o: Transactions.TransactionWithInputInfo) {
        when (o) {
            is CommitTx -> {
                write(0x00); writeInputInfo(o.input); writeBtcObject(o.tx)
            }
            is HtlcTx.HtlcSuccessTx -> {
                write(0x01); writeInputInfo(o.input); writeBtcObject(o.tx); writeByteVector32(o.paymentHash); writeNumber(o.htlcId)
            }
            is HtlcTx.HtlcTimeoutTx -> {
                write(0x02); writeInputInfo(o.input); writeBtcObject(o.tx); writeNumber(o.htlcId)
            }
            is ClaimHtlcTx.ClaimHtlcSuccessTx -> {
                write(0x03); writeInputInfo(o.input); writeBtcObject(o.tx); writeNumber(o.htlcId)
            }
            is ClaimHtlcTx.ClaimHtlcTimeoutTx -> {
                write(0x04); writeInputInfo(o.input); writeBtcObject(o.tx); writeNumber(o.htlcId)
            }
            is ClaimAnchorOutputTx.ClaimLocalAnchorOutputTx -> {
                write(0x05); writeInputInfo(o.input); writeBtcObject(o.tx)
            }
            is ClaimAnchorOutputTx.ClaimRemoteAnchorOutputTx -> {
                write(0x06); writeInputInfo(o.input); writeBtcObject(o.tx)
            }
            is ClaimLocalDelayedOutputTx -> {
                write(0x07); writeInputInfo(o.input); writeBtcObject(o.tx)
            }
            is ClaimRemoteCommitMainOutputTx.ClaimP2WPKHOutputTx -> {
                write(0x08); writeInputInfo(o.input); writeBtcObject(o.tx)
            }
            is ClaimRemoteCommitMainOutputTx.ClaimRemoteDelayedOutputTx -> {
                write(0x09); writeInputInfo(o.input); writeBtcObject(o.tx)
            }
            is MainPenaltyTx -> {
                write(0x0a); writeInputInfo(o.input); writeBtcObject(o.tx)
            }
            is HtlcPenaltyTx -> {
                write(0x0b); writeInputInfo(o.input); writeBtcObject(o.tx)
            }
            is ClaimHtlcDelayedOutputPenaltyTx -> {
                write(0x0c); writeInputInfo(o.input); writeBtcObject(o.tx)
            }
            is ClosingTx -> {
                write(0x0d); writeInputInfo(o.input); writeBtcObject(o.tx); writeNullable(o.toLocalIndex) { writeNumber(it) }
            }
            is SpliceTx -> {
                write(0x0e); writeInputInfo(o.input); writeBtcObject(o.tx)
            }
        }
    }

    private fun Output.writeClosingFeerates(o: ClosingFeerates): Unit = o.run {
        writeNumber(preferred.toLong())
        writeNumber(min.toLong())
        writeNumber(max.toLong())
    }

    private fun Output.writeNumber(o: Number): Unit = LightningCodecs.writeBigSize(o.toLong(), this)

    private fun Output.writeBoolean(o: Boolean): Unit = if (o) write(1) else write(0)

    private fun Output.writeString(o: String): Unit = writeDelimited(o.encodeToByteArray())

    private fun Output.writeByteVector32(o: ByteVector32) = write(o.toByteArray())

    private fun Output.writeByteVector64(o: ByteVector64) = write(o.toByteArray())

    private fun Output.writePublicKey(o: PublicKey) = write(o.value.toByteArray())

    private fun Output.writeDelimited(o: ByteArray) {
        writeNumber(o.size)
        write(o)
    }

    private fun <T : BtcSerializable<T>> Output.writeBtcObject(o: T): Unit = writeDelimited(o.serializer().write(o))

    private fun Output.writeLightningMessage(o: LightningMessage) = writeDelimited(LightningMessage.encode(o))

    private fun <T> Output.writeCollection(o: Collection<T>, writeElem: (T) -> Unit) {
        writeNumber(o.size)
        o.forEach { writeElem(it) }
    }

    private fun <L, R> Output.writeEither(o: Either<L, R>, writeLeft: (L) -> Unit, writeRight: (R) -> Unit) = when (o) {
        is Either.Left -> {
            write(0); writeLeft(o.value)
        }
        is Either.Right -> {
            write(1); writeRight(o.value)
        }
    }

    private fun <T : Any> Output.writeNullable(o: T?, writeNotNull: (T) -> Unit) = when (o) {
        is T -> {
            write(1); writeNotNull(o)
        }
        else -> write(0)
    }
}