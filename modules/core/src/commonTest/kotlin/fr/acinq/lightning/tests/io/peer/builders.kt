package fr.acinq.lightning.tests.io.peer

import fr.acinq.bitcoin.Block
import fr.acinq.bitcoin.ByteVector32
import fr.acinq.bitcoin.PrivateKey
import fr.acinq.lightning.NodeParams
import fr.acinq.lightning.PeerConnected
import fr.acinq.lightning.WalletParams
import fr.acinq.lightning.blockchain.electrum.ElectrumClient
import fr.acinq.lightning.blockchain.electrum.ElectrumWatcher
import fr.acinq.lightning.blockchain.fee.FeeratePerByte
import fr.acinq.lightning.blockchain.fee.FeeratePerKw
import fr.acinq.lightning.blockchain.fee.OnChainFeerates
import fr.acinq.lightning.channel.LNChannel
import fr.acinq.lightning.channel.states.ChannelStateWithCommitments
import fr.acinq.lightning.channel.states.Normal
import fr.acinq.lightning.channel.states.PersistedChannelState
import fr.acinq.lightning.channel.states.Syncing
import fr.acinq.lightning.db.InMemoryDatabases
import fr.acinq.lightning.io.*
import fr.acinq.lightning.logging.MDCLogger
import fr.acinq.lightning.tests.TestConstants
import fr.acinq.lightning.tests.utils.testLoggerFactory
import fr.acinq.lightning.utils.sat
import fr.acinq.lightning.wire.*
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.channels.Channel
import kotlinx.coroutines.flow.Flow
import kotlinx.coroutines.flow.filterIsInstance
import kotlinx.coroutines.flow.first
import kotlinx.coroutines.flow.flow
import kotlinx.coroutines.isActive
import kotlinx.coroutines.joinAll
import kotlinx.coroutines.launch

suspend fun newPeers(
    scope: CoroutineScope,
    nodeParams: Pair<NodeParams, NodeParams>,
    walletParams: Pair<WalletParams, WalletParams>,
    initChannels: List<Pair<LNChannel<PersistedChannelState>, LNChannel<PersistedChannelState>>> = emptyList(),
    automateMessaging: Boolean = true
): PeerTuple {
    val alice = buildPeer(scope, nodeParams.first, walletParams.first, databases = InMemoryDatabases().apply {
        initChannels.forEach { channels.addOrUpdateChannel(it.first.state) }
    })
    val bob = buildPeer(scope, nodeParams.second, walletParams.second, databases = InMemoryDatabases().apply {
        initChannels.forEach { channels.addOrUpdateChannel(it.second.state) }
    })
    return connect(scope, 0, alice, bob, initChannels.size, expectChannelReady = true, automateMessaging)
}

suspend fun connect(
    scope: CoroutineScope,
    connectionId: Long,
    alice: Peer,
    bob: Peer,
    channelsCount: Int,
    expectChannelReady: Boolean = true,
    automateMessaging: Boolean = true
): PeerTuple {
    val logger = MDCLogger(testLoggerFactory.newLogger("PeerConnection"))
    val aliceConnection = PeerConnection(connectionId, Channel(Channel.UNLIMITED), logger)
    val bobConnection = PeerConnection(connectionId, Channel(Channel.UNLIMITED), logger)
    alice.send(Connected(aliceConnection))
    bob.send(Connected(bobConnection))

    // Create collectors for Alice and Bob output messages
    val bob2alice = flow {
        while (scope.isActive) {
            val msg = bobConnection.output.receive()
            println("[connection #$connectionId] Bob sends $msg")
            emit(msg)
        }
    }
    val alice2bob = flow {
        while (scope.isActive) {
            val msg = aliceConnection.output.receive()
            println("[connection #$connectionId] Alice sends $msg")
            emit(msg)
        }
    }

    // Initialize Bob with Alice's features.
    val aliceInit = Init(alice.nodeParams.features.initFeatures(), listOf(Block.RegtestGenesisBlock.hash.value), TestConstants.fundingRates)
    bob.send(MessageReceived(bobConnection.id, aliceInit))
    // Initialize Alice with Bob's features.
    val bobInit = Init(bob.nodeParams.features.initFeatures(), listOf(Block.RegtestGenesisBlock.hash.value), TestConstants.fundingRates)
    alice.send(MessageReceived(aliceConnection.id, bobInit))

    // Initialize Alice and Bob's current feerates.
    alice.send(MessageReceived(aliceConnection.id, RecommendedFeerates(Block.RegtestGenesisBlock.hash, fundingFeerate = FeeratePerKw(FeeratePerByte(20.sat)), commitmentFeerate = FeeratePerKw(FeeratePerByte(1.sat)))))
    bob.send(MessageReceived(bobConnection.id, RecommendedFeerates(Block.RegtestGenesisBlock.hash, fundingFeerate = FeeratePerKw(FeeratePerByte(20.sat)), commitmentFeerate = FeeratePerKw(FeeratePerByte(1.sat)))))

    if (channelsCount > 0) {
        // When there are multiple channels, the channel_reestablish and channel_ready messages from different channels
        // may be interleaved, so we cannot guarantee a deterministic ordering and thus need independent coroutines.
        val channelReestablish = listOf(
            scope.launch { (0 until channelsCount).forEach { _ -> bob.forward(alice2bob.filterIsInstance<ChannelReestablish>().first(), connectionId) } },
            scope.launch { (0 until channelsCount).forEach { _ -> alice.forward(bob2alice.filterIsInstance<ChannelReestablish>().first(), connectionId) } }
        )
        val channelReady = when (expectChannelReady) {
            true -> listOf(
                scope.launch { (0 until channelsCount).forEach { _ -> bob.forward(alice2bob.filterIsInstance<ChannelReady>().first(), connectionId) } },
                scope.launch { (0 until channelsCount).forEach { _ -> alice.forward(bob2alice.filterIsInstance<ChannelReady>().first(), connectionId) } },
            )
            false -> listOf()
        }
        (channelReestablish + channelReady).joinAll()
    }

    // Wait until the Peers are ready
    alice.nodeParams.nodeEvents.first { it == PeerConnected(bob.nodeParams.nodeId, bobInit) }
    bob.nodeParams.nodeEvents.first { it == PeerConnected(alice.nodeParams.nodeId, aliceInit) }

    // Wait until the Channels are synchronised
    alice.channelsFlow.first { it.size == channelsCount && it.values.all { state -> state is Normal } }
    bob.channelsFlow.first { it.size == channelsCount && it.values.all { state -> state is Normal } }

    if (automateMessaging) {
        scope.launch {
            bob2alice.collect {
                alice.send(MessageReceived(connectionId, it))
            }
        }
        scope.launch {
            alice2bob.collect {
                bob.send(MessageReceived(connectionId, it))
            }
        }
    }

    return PeerTuple(alice, bob, alice2bob, bob2alice)
}

suspend fun CoroutineScope.newPeer(
    nodeParams: NodeParams,
    walletParams: WalletParams,
    remotedNodeChannelState: LNChannel<ChannelStateWithCommitments>? = null,
    setupDatabases: suspend InMemoryDatabases.() -> Unit = {},
): Peer {
    val db = InMemoryDatabases().apply { setupDatabases(this) }

    val peer = buildPeer(this, nodeParams, walletParams, db)

    val logger = MDCLogger(nodeParams.loggerFactory.newLogger("PeerConnection"))
    val connection = PeerConnection(0, Channel(Channel.UNLIMITED), logger)
    peer.send(Connected(connection))

    remotedNodeChannelState?.let { state ->
        // send Init from remote node
        val theirInit = Init(features = state.ctx.staticParams.nodeParams.features.initFeatures())
        peer.send(MessageReceived(connection.id, theirInit))

        peer.channelsFlow.first {
            it.values.size == peer.db.channels.listLocalChannels().size && it.values.all { channelState -> channelState is Syncing }
        }

        val yourLastPerCommitmentSecret = state.commitments.remotePerCommitmentSecrets.lastIndex?.let { state.commitments.remotePerCommitmentSecrets.getHash(it) } ?: ByteVector32.Zeroes
        val myCurrentPerCommitmentPoint = peer.nodeParams.keyManager.channelKeys(state.commitments.params.localParams.fundingKeyPath).commitmentPoint(state.commitments.localCommitIndex)

        val channelReestablish = ChannelReestablish(
            channelId = state.channelId,
            nextLocalCommitmentNumber = state.commitments.localCommitIndex + 1,
            nextRemoteRevocationNumber = state.commitments.remoteCommitIndex,
            yourLastCommitmentSecret = PrivateKey(yourLastPerCommitmentSecret),
            myCurrentPerCommitmentPoint = myCurrentPerCommitmentPoint
        )

        peer.send(MessageReceived(connection.id, channelReestablish))
    }

    peer.channelsFlow.first {
        it.values.size == peer.db.channels.listLocalChannels().size && it.values.all { channelState -> channelState is Normal }
    }

    return peer
}

suspend fun buildPeer(
    scope: CoroutineScope,
    nodeParams: NodeParams,
    walletParams: WalletParams,
    databases: InMemoryDatabases = InMemoryDatabases(),
    currentTip: Int = 0
): Peer {
    val electrum = ElectrumClient(scope, nodeParams.loggerFactory)
    val watcher = ElectrumWatcher(electrum, scope, nodeParams.loggerFactory)
    val peer = Peer(nodeParams, walletParams, watcher.client, watcher, databases, TcpSocket.Builder(), scope)
    peer.currentTipFlow.value = currentTip
    peer.onChainFeeratesFlow.value = OnChainFeerates(
        fundingFeerate = FeeratePerKw(FeeratePerByte(5.sat)),
        mutualCloseFeerate = FeeratePerKw(FeeratePerByte(10.sat)),
        claimMainFeerate = FeeratePerKw(FeeratePerByte(20.sat)),
        fastFeerate = FeeratePerKw(FeeratePerByte(50.sat))
    )
    val logger = MDCLogger(nodeParams.loggerFactory.newLogger("PeerConnection"))
    val connection = PeerConnection(0, Channel(Channel.UNLIMITED), logger)
    peer.send(Connected(connection))

    return peer
}

data class PeerTuple(val alice: Peer, val bob: Peer, val alice2bob: Flow<LightningMessage>, val bob2alice: Flow<LightningMessage>)