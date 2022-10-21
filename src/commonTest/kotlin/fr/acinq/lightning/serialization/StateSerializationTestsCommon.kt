package fr.acinq.lightning.serialization

import fr.acinq.lightning.Feature
import fr.acinq.lightning.Lightning.randomKey
import fr.acinq.lightning.MilliSatoshi
import fr.acinq.lightning.channel.*
import fr.acinq.lightning.serialization.Encryption.from
import fr.acinq.lightning.tests.utils.LightningTestSuite
import fr.acinq.lightning.wire.CommitSig
import fr.acinq.lightning.wire.EncryptedChannelData
import fr.acinq.lightning.wire.LightningMessage
import fr.acinq.secp256k1.Hex
import kotlin.math.max
import kotlin.test.*

class StateSerializationTestsCommon : LightningTestSuite() {

    @Test
    fun `serialize normal state`() {
        val (alice, bob) = TestsHelper.reachNormal()
        val bytes = Serialization.serialize(alice.state)
        val check = Serialization.deserialize(bytes)
        assertEquals(alice.state, check)

        val bytes1 = Serialization.serialize(bob.state)
        val check1 = Serialization.deserialize(bytes1)
        assertEquals(bob.state, check1)
    }

    @Test
    fun `encrypt - decrypt normal state`() {
        val (alice, bob) = TestsHelper.reachNormal()
        val priv = randomKey()
        val bytes = EncryptedChannelData.from(priv, alice.state)
        val check = ChannelStateWithCommitments.from(priv, bytes)
        assertEquals(alice.state, check)

        val bytes1 = EncryptedChannelData.from(priv, bob.state)
        val check1 = ChannelStateWithCommitments.from(priv, bytes1)
        assertEquals(bob.state, check1)
    }
    
    @Ignore
    @Test
    fun `don't restore data from a different chain`() {
        val (alice, _) = TestsHelper.reachNormal()
        val priv = randomKey()
        val bytes = EncryptedChannelData.from(priv, alice.state)
        val check = ChannelStateWithCommitments.from(priv, bytes)
        assertEquals(alice.state, check)

        // we cannot test the exception's error message anymore because v2 serialization will fail (invalid chain) then we'll try v1 serialization which will return a different error
        assertFails {
            ChannelStateWithCommitments.from(priv, bytes)
        }
    }

    @Test
    fun `backwards compatibility test`() {
        val bin = Hex.decode(
            "0000000200000b1b0000002a66722e6163696e712e6c696768746e696e672e73657269616c697a6174696f6e2e76322e4e6f726d616c0000002006226e46111a0b59caaf126043eb5bbf28c34f3a5e332a1fc7b2b73cf188910f0000002103f569caf6811602c3bc63cad63b4d5cfe808a3f269da354dbc47829f85a25ac22000002970000000b426c6f636b4865616465720000005000000020f230b4cb3e4981959011a8b718bc90c7a6a0734625f4e0d70fbfd647a51ee0465185854435bbd3d294ff46259a56ea557c2fd24fc0cb28f6931679426645e58c46ea8a60ffff7f2001000000000000000000927c000000000000927c000000000000927c000000040000000f0000002103ee444f9b8e2de8759a501c89b8532b6be2dcc5d8c8a125256c508f313106121600000004112a4ebd9482ebcc573126355bb80eddd51ca6f93ff4ef605a476ee53523642a0000000000000222000000012a05f20000000000000002580000000000000001000007e00000001e00000000160014dfbd041384ae68aaacebabdcdf4a9447a48ee754000000080000003066722e6163696e712e6c696768746e696e672e466561747572652e4f7074696f6e446174614c6f737350726f74656374000000002e66722e6163696e712e6c696768746e696e672e466561747572652e5661726961626c654c656e6774684f6e696f6e010000002866722e6163696e712e6c696768746e696e672e466561747572652e5061796d656e74536563726574010000003066722e6163696e712e6c696768746e696e672e466561747572652e42617369634d756c7469506172745061796d656e74010000002066722e6163696e712e6c696768746e696e672e466561747572652e57756d626f010000002a66722e6163696e712e6c696768746e696e672e466561747572652e53746174696352656d6f74654b6579010000002866722e6163696e712e6c696768746e696e672e466561747572652e416e63686f724f757470757473010000002c66722e6163696e712e6c696768746e696e672e466561747572652e5472616d706f6c696e655061796d656e7401000000000000002103f569caf6811602c3bc63cad63b4d5cfe808a3f269da354dbc47829f85a25ac220000000000000222000000012a05f20000000000000000000000000000000001000002d00000001e00000021035781540c52af9afd2d9980663b83fae0cc595dba65edbfccac50fa8a27d95095000000210289673a7292949b0b5a3c0f833a97e80f2954cfd2e0f8430c0bd4d7f8d2eedd270000002102d2bb1625229945acf450aa86ec98df8f6da4791d7b34dc9832e86d359d0973520000002103185eb65e3add9a1c0dbba3e900bf061d6979b24a6e0ef5d38ef8dc8029633f130000002102e915accfed9301352ce527b90357d1416720b24a907982814b620fcf4234a5ae000000080000003066722e6163696e712e6c696768746e696e672e466561747572652e4f7074696f6e446174614c6f737350726f74656374010000002e66722e6163696e712e6c696768746e696e672e466561747572652e4368616e6e656c52616e676551756572696573010000002e66722e6163696e712e6c696768746e696e672e466561747572652e5661726961626c654c656e6774684f6e696f6e010000003666722e6163696e712e6c696768746e696e672e466561747572652e4368616e6e656c52616e676551756572696573457874656e646564010000002a66722e6163696e712e6c696768746e696e672e466561747572652e53746174696352656d6f74654b6579010000002866722e6163696e712e6c696768746e696e672e466561747572652e5061796d656e74536563726574010000003066722e6163696e712e6c696768746e696e672e466561747572652e42617369634d756c7469506172745061796d656e74010000002066722e6163696e712e6c696768746e696e672e466561747572652e57756d626f01000000000000000000000000020000000000000000000009c40000000008e193280000000001980138000000084f7574506f696e74000000247f7886e98bdd16db8b09ab5dc928466528fae6419812174fd29dbd67f1aae290010000000000000554784f75740000002b7cae02000000000022002093e6314ab78e7dd6d1e1b7874e636f1d3ac3ceecd2769a8e3e266c0b27415e0e000000475221035781540c52af9afd2d9980663b83fae0cc595dba65edbfccac50fa8a27d950952103b827ea57009817e15d1979454f6c07ae67c7b900c9c058f836ac32059379a5fa52ae0000000b5472616e73616374696f6e000001bc020000000001017f7886e98bdd16db8b09ab5dc928466528fae6419812174fd29dbd67f1aae290010000000009984c80044a010000000000002200204a88e3d85675703ba0e3ffa9c6cc05a92e3af95d007a2ba41dbbd6fb9228cadb4a0100000000000022002089aee362f8e4cf3ef4dc26a1688309c1f57613922ee7914d5466443f3ec2f326e55a00000000000022002070f0b3dbd7855088f2e809456cdc06573c892da9565990745193b11bc1f09be309460200000000002200200aac45f49787442db69da7ddfccb66e16e6475cb265abe5362f3769b5bde338f040048304502210085eeb8a4a7ece4edad760470af6a918eb8ae4878b86586e7d8ff74149cdbe5f002207f97c5de7ab0a5e5008d7cb09309e12443be46492cae32253fe870bd75add740014730440220149a1a6b3b3fcc622ff2f325df5b8546e6c2b5e662c84d6e5513829dd1d367a8022026bcb06ab6cb2e106dfc339f8f61351bb2ae892a23d220878a9343de26411b8b01475221035781540c52af9afd2d9980663b83fae0cc595dba65edbfccac50fa8a27d950952103b827ea57009817e15d1979454f6c07ae67c7b900c9c058f836ac32059379a5fa52ae18d44f200000000000000000000000020000000000000000000009c400000000019801380000000008e1932800000020bf4c124b9301262ebee9e758f91234c55677a6f5f9116a174207a91ce4dfac87000000210371f992c2c203ed137cc7ee5f53af35ded8d444263279cb514799e4749753fcf0000000000000000000000000000000000000000000000000000000000000000000000000000000010000000001000100000021028cd4c069ef4196ac101a81186ad0ec23a4958f3c4cd2478f4b54eba3879c36fb000000084f7574506f696e74000000247f7886e98bdd16db8b09ab5dc928466528fae6419812174fd29dbd67f1aae290010000000000000554784f75740000002b7cae02000000000022002093e6314ab78e7dd6d1e1b7874e636f1d3ac3ceecd2769a8e3e266c0b27415e0e000000475221035781540c52af9afd2d9980663b83fae0cc595dba65edbfccac50fa8a27d950952103b827ea57009817e15d1979454f6c07ae67c7b900c9c058f836ac32059379a5fa52ae000000010000003f30303030303030303030303030303030313131313131313131313131313131313131313131313131313131313131313131313131313131313131313131313100000020ce4c68bdf7ef03afa1d345fc3420794116f65f18865c77644063aa6f1b901a51010000fffffffffffe000000207f7886e98bdd16db8b09ab5dc928466528fae6419812174fd29dbd67f1aae291000000000000001d550f0001000000000040815ae5fc117aa1032dadef9392fa8d358965122d28892359e6a3c93717e2e0a13fc6c378680b4224fed354a94417971b148042c29c15165711356746921d48030000002006226e46111a0b59caaf126043eb5bbf28c34f3a5e332a1fc7b2b73cf188910f0000001d550f000100000000608aea56010000000090000000000000000100000000000003e8000000000000006401000000000a79946000000000000000"
        )
        val state = Serialization.deserialize(bin)
        assertIs<Normal>(state)
        assertEquals(state.commitments.channelConfig, ChannelConfig.standard)
        assertEquals(state.commitments.channelFeatures, ChannelFeatures(setOf(Feature.Wumbo, Feature.StaticRemoteKey, Feature.AnchorOutputs, Feature.ZeroReserveChannels, Feature.ZeroConfChannels)))
    }

    @Test
    fun `maximum number of HTLCs that is safe to use`() {
        val (alice, bob) = TestsHelper.reachNormal()
        assertTrue(bob.commitments.localParams.features.hasFeature(Feature.ChannelBackupClient))

        tailrec fun addHtlcs(sender: LNChannel<Normal>, receiver: LNChannel<Normal>, amount: MilliSatoshi, count: Int): Pair<LNChannel<Normal>, LNChannel<Normal>> = if (count == 0) Pair(sender, receiver) else {
            val (p, _) = TestsHelper.addHtlc(amount, sender, receiver)
            val (alice1, bob1) = p
            assertIs<LNChannel<Normal>>(alice1)
            assertIs<LNChannel<Normal>>(bob1)
            addHtlcs(alice1, bob1, amount, count - 1)
        }

        fun commitSigSize(maxIncoming: Int, maxOutgoing: Int): Int {
            val (alice1, bob1) = addHtlcs(alice, bob, MilliSatoshi(6000_000), maxOutgoing)
            val (bob2, alice2) = addHtlcs(bob1, alice1, MilliSatoshi(6000_000), maxIncoming)
            val (_, actions) = alice2.process(ChannelCommand.ExecuteCommand(CMD_SIGN))
            val commitSig0 = actions.findOutgoingMessage<CommitSig>()

            val (bob3, actions1) = bob2.process(ChannelCommand.MessageReceived(commitSig0))
            val commandSign0 = actions1.findCommand<CMD_SIGN>()

            val (_, actions2) = bob3.process(ChannelCommand.ExecuteCommand(commandSign0))
            val commitSig1 = actions2.findOutgoingMessage<CommitSig>()

            val bina = LightningMessage.encode(commitSig0)
            val binb = LightningMessage.encode(commitSig1)
            return max(bina.size, binb.size)
        }

        // with 6 incoming payments and 6 outgoing payments, we can still add our encrypted backup to commig_sig messages
        assertTrue(commitSigSize(6, 6) < 65000)
    }
}
