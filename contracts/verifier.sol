// This file is MIT Licensed.
//
// Copyright 2017 Christian Reitwiessner
// Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated documentation files (the "Software"), to deal in the Software without restriction, including without limitation the rights to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the Software, and to permit persons to whom the Software is furnished to do so, subject to the following conditions:
// The above copyright notice and this permission notice shall be included in all copies or substantial portions of the Software.
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
pragma solidity ^0.8.0;
library Pairing {
    struct G1Point {
        uint X;
        uint Y;
    }
    // Encoding of field elements is: X[0] * z + X[1]
    struct G2Point {
        uint[2] X;
        uint[2] Y;
    }
    /// @return the generator of G1
    function P1() pure internal returns (G1Point memory) {
        return G1Point(1, 2);
    }
    /// @return the generator of G2
    function P2() pure internal returns (G2Point memory) {
        return G2Point(
            [10857046999023057135944570762232829481370756359578518086990519993285655852781,
             11559732032986387107991004021392285783925812861821192530917403151452391805634],
            [8495653923123431417604973247489272438418190587263600148770280649306958101930,
             4082367875863433681332203403145435568316851327593401208105741076214120093531]
        );
    }
    /// @return the negation of p, i.e. p.addition(p.negate()) should be zero.
    function negate(G1Point memory p) pure internal returns (G1Point memory) {
        // The prime q in the base field F_q for G1
        uint q = 21888242871839275222246405745257275088696311157297823662689037894645226208583;
        if (p.X == 0 && p.Y == 0)
            return G1Point(0, 0);
        return G1Point(p.X, q - (p.Y % q));
    }
    /// @return r the sum of two points of G1
    function addition(G1Point memory p1, G1Point memory p2) internal view returns (G1Point memory r) {
        uint[4] memory input;
        input[0] = p1.X;
        input[1] = p1.Y;
        input[2] = p2.X;
        input[3] = p2.Y;
        bool success;
        assembly {
            success := staticcall(sub(gas(), 2000), 6, input, 0xc0, r, 0x60)
            // Use "invalid" to make gas estimation work
            switch success case 0 { invalid() }
        }
        require(success);
    }


    /// @return r the product of a point on G1 and a scalar, i.e.
    /// p == p.scalar_mul(1) and p.addition(p) == p.scalar_mul(2) for all points p.
    function scalar_mul(G1Point memory p, uint s) internal view returns (G1Point memory r) {
        uint[3] memory input;
        input[0] = p.X;
        input[1] = p.Y;
        input[2] = s;
        bool success;
        assembly {
            success := staticcall(sub(gas(), 2000), 7, input, 0x80, r, 0x60)
            // Use "invalid" to make gas estimation work
            switch success case 0 { invalid() }
        }
        require (success);
    }
    /// @return the result of computing the pairing check
    /// e(p1[0], p2[0]) *  .... * e(p1[n], p2[n]) == 1
    /// For example pairing([P1(), P1().negate()], [P2(), P2()]) should
    /// return true.
    function pairing(G1Point[] memory p1, G2Point[] memory p2) internal view returns (bool) {
        require(p1.length == p2.length);
        uint elements = p1.length;
        uint inputSize = elements * 6;
        uint[] memory input = new uint[](inputSize);
        for (uint i = 0; i < elements; i++)
        {
            input[i * 6 + 0] = p1[i].X;
            input[i * 6 + 1] = p1[i].Y;
            input[i * 6 + 2] = p2[i].X[1];
            input[i * 6 + 3] = p2[i].X[0];
            input[i * 6 + 4] = p2[i].Y[1];
            input[i * 6 + 5] = p2[i].Y[0];
        }
        uint[1] memory out;
        bool success;
        assembly {
            success := staticcall(sub(gas(), 2000), 8, add(input, 0x20), mul(inputSize, 0x20), out, 0x20)
            // Use "invalid" to make gas estimation work
            switch success case 0 { invalid() }
        }
        require(success);
        return out[0] != 0;
    }
    /// Convenience method for a pairing check for two pairs.
    function pairingProd2(G1Point memory a1, G2Point memory a2, G1Point memory b1, G2Point memory b2) internal view returns (bool) {
        G1Point[] memory p1 = new G1Point[](2);
        G2Point[] memory p2 = new G2Point[](2);
        p1[0] = a1;
        p1[1] = b1;
        p2[0] = a2;
        p2[1] = b2;
        return pairing(p1, p2);
    }
    /// Convenience method for a pairing check for three pairs.
    function pairingProd3(
            G1Point memory a1, G2Point memory a2,
            G1Point memory b1, G2Point memory b2,
            G1Point memory c1, G2Point memory c2
    ) internal view returns (bool) {
        G1Point[] memory p1 = new G1Point[](3);
        G2Point[] memory p2 = new G2Point[](3);
        p1[0] = a1;
        p1[1] = b1;
        p1[2] = c1;
        p2[0] = a2;
        p2[1] = b2;
        p2[2] = c2;
        return pairing(p1, p2);
    }
    /// Convenience method for a pairing check for four pairs.
    function pairingProd4(
            G1Point memory a1, G2Point memory a2,
            G1Point memory b1, G2Point memory b2,
            G1Point memory c1, G2Point memory c2,
            G1Point memory d1, G2Point memory d2
    ) internal view returns (bool) {
        G1Point[] memory p1 = new G1Point[](4);
        G2Point[] memory p2 = new G2Point[](4);
        p1[0] = a1;
        p1[1] = b1;
        p1[2] = c1;
        p1[3] = d1;
        p2[0] = a2;
        p2[1] = b2;
        p2[2] = c2;
        p2[3] = d2;
        return pairing(p1, p2);
    }
}

contract Verifier {
    using Pairing for *;
    struct VerifyingKey {
        Pairing.G1Point alpha;
        Pairing.G2Point beta;
        Pairing.G2Point gamma;
        Pairing.G2Point delta;
        Pairing.G1Point[] gamma_abc;
    }
    struct Proof {
        Pairing.G1Point a;
        Pairing.G2Point b;
        Pairing.G1Point c;
    }
    function verifyingKey() pure internal returns (VerifyingKey memory vk) {
        vk.alpha = Pairing.G1Point(uint256(0x192dc1611960b3593f2c3b6b9a8a73423382b69bd0ac2d31297e69cded679090), uint256(0x2d6a813562b99396ec6889b47397436cb08e753c103ebf03efc3aeee6693d494));
        vk.beta = Pairing.G2Point([uint256(0x1802de4e6d451da2fc6cfe89662fa15779e90ab0242013e3e6104190e8b5081a), uint256(0x09e718919f7bc4d9041696fa96ed860c17fc3ce0475cf61d8914ed481f2c7030)], [uint256(0x0583691f66930ca8bf84be5fb2cc9de13b9ed629e70cf3eba411b8b7edecbe46), uint256(0x052b5596f54404a9f36a7c173d3bf76f2d88139547b569c1c10ecc92a4067abf)]);
        vk.gamma = Pairing.G2Point([uint256(0x262e00f66549d5ab57a57a6b7d8162f2cc7c557bc1fb64adf72c5c1f484f1dfa), uint256(0x0957ced0bfc989278439d43ba5b10d1104399eec9ada8b0b94feae301af91a4f)], [uint256(0x16f1cc431b2f3a17a632fa5ba0b68cef04aa3d6b4c20d67d2aa4784b2ca4788b), uint256(0x0509dde36e1703ff166a9973573055558f94775fdcec609f574ac61c247e15a5)]);
        vk.delta = Pairing.G2Point([uint256(0x104e2044fe7b3a20d258990a9081c8183bec258e4954a397f8e5b6a9d0fd26cd), uint256(0x2d8a6156562c62c0b50a2abf9a333abf185e8a23d8d96130eb021daa3b4e31b6)], [uint256(0x15acd8a8e355821f306e8882c153c2f7af0edebaaf97ccead2811a8cfb5fa0ea), uint256(0x15d6e27c162e24b2107342762a8b35e39850d2be199551cd74f2066c3742329d)]);
        vk.gamma_abc = new Pairing.G1Point[](86);
        vk.gamma_abc[0] = Pairing.G1Point(uint256(0x0bf78c5fe83c3016938c043602cfead0b03fa9e35906f5db2d3649ebb46fb270), uint256(0x20b3d1d5444549626a60a8ad1e53ae18c59e4cfa52a44f2dbd3d9bc9bdc6ba61));
        vk.gamma_abc[1] = Pairing.G1Point(uint256(0x116a77522ffd94e7ac8a9a5d38fb63cd1415a0861df6d4423c316c9fb3ad54d2), uint256(0x10c1383cebf46e95328a4a7fa7102161d1a44432e17af3b6ad42678d970869e2));
        vk.gamma_abc[2] = Pairing.G1Point(uint256(0x05e2b356d1a5e22168bad59cee678d192695b6fcab2c62206385d18d8d12e741), uint256(0x2114f8c86ae45015ad0f9a2821580a1a6d57cb5a7b720805356ebcfcc5925725));
        vk.gamma_abc[3] = Pairing.G1Point(uint256(0x260ed7a024b2efef38e6b4e22961d631705a84ee700c2f4b6eb4163ba137467d), uint256(0x301570918826389fe9e830ebca2452f8f7401eee57ebb1cd5d9d17fd50c17232));
        vk.gamma_abc[4] = Pairing.G1Point(uint256(0x002c2437800a05e1097b8bd9166346dbc377303a3432985e437b25db90a3be4b), uint256(0x29d454a14ea8cd6f1f8a36f3b00b39241c1048a0bd60b5800352ff466283b583));
        vk.gamma_abc[5] = Pairing.G1Point(uint256(0x2bff54cab12c9b52ee372c3eee21e2ec3508f15fc259637e4cdbab7a608fa232), uint256(0x08d34b933928bad82c3927c28d43e7839a943e4200a3b2687a7d3d3f2c8c6387));
        vk.gamma_abc[6] = Pairing.G1Point(uint256(0x19cee4d93813f021c78b4a3b5292ee8a823ed7ae209ab0c63eb0b0234fe11f55), uint256(0x06bd34a47dc7eab446acab6c628343a9b81ac77898abe9f5f156a4423a0d2230));
        vk.gamma_abc[7] = Pairing.G1Point(uint256(0x1860e6904d9c983d9d6cb28e3c2dc57f24dec270757fc9b9ca98cd55bb7f6fca), uint256(0x0e9939ad029a1bec7211722fca45f19f41a2ed3b53f74035a187291a9ccd98a9));
        vk.gamma_abc[8] = Pairing.G1Point(uint256(0x0b128e1eba4cdbb9ff5aa4c67cc8c275b2465b4f0367743ffa1faafa3b0d77e8), uint256(0x1be45c0cc87eb39f34de50da7f83acc0f7975fb089e7ec69c7b45378b5ab4dc5));
        vk.gamma_abc[9] = Pairing.G1Point(uint256(0x29f78cb43e1db2fb6e270cddf9d6f07b1394af942cd1b0b47c28570730735052), uint256(0x0d99fdfab1efeac80399b99ce164b765d611d8d82c3f2b68efac2e274cd990df));
        vk.gamma_abc[10] = Pairing.G1Point(uint256(0x29b56cba011200a79910cd2aa13a0a5858ccb787188b1f0103fc0041738c7ea3), uint256(0x1aeab0f7d46782736db9d9e696d88d66394b770f9819d4713542c7ef19173983));
        vk.gamma_abc[11] = Pairing.G1Point(uint256(0x0d0fdb4efccd66357fdfc1160e103d2f4383f296650488758a193038f41c0c86), uint256(0x0f4f23da2ed445e63a6a7704cf0acc534a2d635330b5a95257d618f7ef22d314));
        vk.gamma_abc[12] = Pairing.G1Point(uint256(0x040e2f46ff58e87164f953df19d1aee55117b1229b15c10e31c52712183cb7ed), uint256(0x06fe568a2666695f9430dec66af3dd5f8b65d731255e0f53dec8b9560a9c21aa));
        vk.gamma_abc[13] = Pairing.G1Point(uint256(0x11850211f96de856079ae7b60db90fc2e1202407c36391a241b860d528577f3d), uint256(0x304fec7080c32ea4ec7184f293ac52d0a2173e3db72aecb6c3364cd1f36358e9));
        vk.gamma_abc[14] = Pairing.G1Point(uint256(0x273bb22e492fb8283751e997b005baaf44c9a863b4373d050c8cd42b463b9ca5), uint256(0x1a43279faa1b158ffd84d40c88533010b301d7ae48a6534f4b54799690c4251b));
        vk.gamma_abc[15] = Pairing.G1Point(uint256(0x1b8f0b90731c185268f179f8e7fc88ce02ff83a768b197af4392dcd619be4c2b), uint256(0x0361c6a92c56f4aeb38f2910c2430581ef33b3a08747437ee1d07ee0eb761b2e));
        vk.gamma_abc[16] = Pairing.G1Point(uint256(0x03d68ce3f7038603cb6cc4e3e41c24188de751a3472b96ef27a6580c4b51c10f), uint256(0x252e7bbf31058ea1d3c46b3d3b0c40c63d516e70f029e807e0b0d27847362dfc));
        vk.gamma_abc[17] = Pairing.G1Point(uint256(0x15c0ba531147b88073ef48bbaba4f97ca43e8b81d1bb1991df3900fd7f996b0c), uint256(0x0b7a21487c2fc03a723f7f5cbbdff61b781422c2d9e41f52f30581209cf19976));
        vk.gamma_abc[18] = Pairing.G1Point(uint256(0x21aeb3e87af782825c03e0b761c0eba67e35f4e03663c14bf6915b7f7eb28950), uint256(0x195a1fe92d11d4ebf35f86db34e0db6181af866509f97e591e0f0273c519e70a));
        vk.gamma_abc[19] = Pairing.G1Point(uint256(0x2171867cce738f826809731f27923de266ad226c3fefa9dabc5336c11505ccb3), uint256(0x1a72edaea166754257d9693a5a628d753e70e84057fa5e3bda88e75fe1db5421));
        vk.gamma_abc[20] = Pairing.G1Point(uint256(0x2295c9c43675a10506276238b69b8409749718097d3a5b7b71f29fc1fc05a67b), uint256(0x1d7e58199ccf95ed079ef989283e60729eb2ed2481d8b81cd1db6a93136219bb));
        vk.gamma_abc[21] = Pairing.G1Point(uint256(0x1ea4c19b6cecee27912d83dce87574ed45dd4909f315bd9a2213b938cc967819), uint256(0x262d0bb3e63a0799b0d35b64a580b68741ab258ebd59ede6c035f28bc5d7202c));
        vk.gamma_abc[22] = Pairing.G1Point(uint256(0x182448abe857f44e0426973f467eace5a8792f02778d3f64f4b0a775cbebb4a7), uint256(0x26d20e0295ab1fe8c67b5fde5feb9708259596416e73257915cc98ae7ea9524f));
        vk.gamma_abc[23] = Pairing.G1Point(uint256(0x2d4b9da5a5be1f185342a70c7b8df92c332cf9520a509247e0c863d69327f2eb), uint256(0x2310af09f267adb8f9d058c29eea68cac00db162c90260db939b56d7794901a6));
        vk.gamma_abc[24] = Pairing.G1Point(uint256(0x1e411e33d53bf5740b7b9aae5b35565966897173c211696c95f84eabd571fba8), uint256(0x2177c9aac5a11a7aa3f67f65e56197e7edec191fcbacf6af4d878d4adc06c3ee));
        vk.gamma_abc[25] = Pairing.G1Point(uint256(0x034a1b433c20bcc1f759795fbdb50a2d59d9b4d9d96395a84f421f775d22f56b), uint256(0x0f9b64889b6e47937c481303b85754c6d85b7896a52fa63076edbdfec957d828));
        vk.gamma_abc[26] = Pairing.G1Point(uint256(0x1f02966fa6c2aff42fd4eb26952f9e105d8c7e5e6bc1203b7a88963f564054ae), uint256(0x166726d0d91cc2917f8371f1220cdb6d177d8a1fdf5a09700d58d9191a53a4e9));
        vk.gamma_abc[27] = Pairing.G1Point(uint256(0x06562968606c8009c48af7c0bda3682a65d4c0a1c81eee45da9fbbfe770dde93), uint256(0x0fb1e070b0943ea3e9ddad7faac87129bb99ec59a665438a152c4c8288598b78));
        vk.gamma_abc[28] = Pairing.G1Point(uint256(0x08319b42844e2198c39e6dd2d29a8ef4948b97fcfd32e9f353a7e8abc5c740cf), uint256(0x0ecb6380e5c39f31b9cdc4648a3834c71aadaf25016719eb94617e580ea10ebf));
        vk.gamma_abc[29] = Pairing.G1Point(uint256(0x08ef6fcf0fd76592f4dba0848b83333a1ee84e35e0febf8beda3fff30029545e), uint256(0x0c3b92db0ab7118fcb1c7e229eab23c06ebe0b75df9602bf660fe8707da0c93f));
        vk.gamma_abc[30] = Pairing.G1Point(uint256(0x025659ca369f9459bf3dd9163d6a6cfd6686fd133aa8310850f0b1e889c9d5f2), uint256(0x29b0cc042998637169524f10956415fed24a6e16eb1c53ba881a26902e122ae4));
        vk.gamma_abc[31] = Pairing.G1Point(uint256(0x033991ff684e035d1d7f34fa4a9c57990742e8d9e382f63f2a384320acfada2f), uint256(0x199bd26e921b4253561c4567ea34d02d75cb3b361ca6fbc2590b728238b536c7));
        vk.gamma_abc[32] = Pairing.G1Point(uint256(0x1ccb45c59cabc3020e9eefc30ce50b72e651784ac55aefe26fdfc9e2e16c44df), uint256(0x016428f246c48aafe034548063b5e617010c69288632950246f74b1b5a662afb));
        vk.gamma_abc[33] = Pairing.G1Point(uint256(0x021319dc5f71f76119ce8580f6bfcec52fbea7a20ef9a5d931b78d084c999822), uint256(0x2ce44c6f871011e0ac90f98d7e05155bd5adef4fd2b0129500c889574ee6b36f));
        vk.gamma_abc[34] = Pairing.G1Point(uint256(0x0c9050542376bc4445b3c9d987d12d5674fa23ef20a341c54af4da592429d386), uint256(0x14b1c9800f7a88571fd8432348dcc1c847d344dd0d7ec9e4d001ff8b35defb8c));
        vk.gamma_abc[35] = Pairing.G1Point(uint256(0x1e81877f821da8472e06ee8b72d01943767e0a2f2f39f9c02e2bcf813acfac1c), uint256(0x243cdc214da14eff940e294c5ba3afcb2051ef1d39f3252335fd27207bbc8816));
        vk.gamma_abc[36] = Pairing.G1Point(uint256(0x18bef34137f23958478e0d46d9d1d2544cb92312f548273f4ecb46c9e1975491), uint256(0x0c09071d3f513b8be892b1bfcab2bff20bb4be0056f4389c0e0f7379dd45c459));
        vk.gamma_abc[37] = Pairing.G1Point(uint256(0x12b571ff6e3b31a4882554e33727c886a417e03c55fbb159bd84c45e981e999f), uint256(0x2a84719e7e1a69328e6ebb9beb6621b5d80bc04110915075315be7fcb3ed00da));
        vk.gamma_abc[38] = Pairing.G1Point(uint256(0x1312f2d80dd114a838696e27046169e2cdac07218c2aa0bf7c64f6795a1864ae), uint256(0x26f68c474bf712b8b074d18f035889fcef2b2c25b85c61760f56c742e42f3265));
        vk.gamma_abc[39] = Pairing.G1Point(uint256(0x116f0a3bf180cb0fe9a94b08014898eb985e1784fe5338e318818826a44286c8), uint256(0x0ae32d1e5018dde587d23906f60781a4cf5416143943777617cc58a174682b3c));
        vk.gamma_abc[40] = Pairing.G1Point(uint256(0x1ba6cefc001f9c16cf8f0680fb597f11f40b3e25261aa397b32b1e9ecd5249d2), uint256(0x0d5d3ff3f57a035cdf05dce895d2440c49e2f4e03d8b6bf8f22c6bec1769ad4d));
        vk.gamma_abc[41] = Pairing.G1Point(uint256(0x23a741d68c4572adddcb812a58aa6dbbdfbd37ad9871a6978bd51d6d05fb719b), uint256(0x2b5ab947750b22739bcfc4871ce816f69f8467aaa8ffd7b4edcd4b3067bf04ed));
        vk.gamma_abc[42] = Pairing.G1Point(uint256(0x0ee378815c3fd07a9c818a232388b07a14ecf447ebe7920c68d9355934ba9a89), uint256(0x1a3482f7fcd4c4bdf897e31bc9c4a01c78f9b7fa2fdafdfadfbc512aae3fcda2));
        vk.gamma_abc[43] = Pairing.G1Point(uint256(0x1ca04d66731226104872122441bba45466cad4ffd97a9b3d9bdb82fc58f82a34), uint256(0x1f5f9cf1f2085b5f0ca446b3c874dd62fc114a38f09b60952855edb980970138));
        vk.gamma_abc[44] = Pairing.G1Point(uint256(0x1db8ed38e008d47b973c7fc04508873e27fee64492d70c23b5345925fc9b662b), uint256(0x196059762f15289af7717c2adbb1e658b0988d3c97b532b1fddae922e858be89));
        vk.gamma_abc[45] = Pairing.G1Point(uint256(0x13dd5707f94bf9209097ca6d9fae525e53feb6dbe0079fc11b1a7e81c2bb011f), uint256(0x2b133e0b11f60381b2d8ab9310b48434d86f6e44971e4d9dd2da4cd391fa1e4e));
        vk.gamma_abc[46] = Pairing.G1Point(uint256(0x09efce218cab5f12bd2f5390309d06a79ddaabbe3ad78d170735fb94ea2f5cfb), uint256(0x0a6344f795577033b1b26a6323a7364f493e12f1c6a6a0640c21f00499a7223a));
        vk.gamma_abc[47] = Pairing.G1Point(uint256(0x235d34fed9ddad24dca40094a4927aaa4959392dc3dcefd1628130171b491f49), uint256(0x0a1fbb5af23cca0c29a4f2846109deb147407bce8fbc2889fd8a5be2bce05296));
        vk.gamma_abc[48] = Pairing.G1Point(uint256(0x234da0fc2807889e5637c1ad21433157c9148b28ae8471f96a92f50b60cfc064), uint256(0x2adc2138ec92f4899b0e5374c1da0c039d3649bdf97842472ce5bb4ce530f36f));
        vk.gamma_abc[49] = Pairing.G1Point(uint256(0x0fd3f94c6ee6465976fe98d0d0f95cdca223b792d4c53552c47f62235c26aeae), uint256(0x203ecd1d5f843cd6feb6bc01bc3db98066e715d33fa13d6542525e623eaf256a));
        vk.gamma_abc[50] = Pairing.G1Point(uint256(0x1ff426b1cebf4aa7e3ddcf8f3da2f21f4179829f20faeacda794c0503c4669ee), uint256(0x301dbee98cea774af3424e2afbd6b1e0fc18d153651ba31377893cc7f687a6bb));
        vk.gamma_abc[51] = Pairing.G1Point(uint256(0x1d68531d75cc2cc648b72498e9ac47d9e2c29cf5b5a745f336bc8480f940781b), uint256(0x23c1dde3a8c60425f50f87c2de4a6626d973329cf2bd796ea3692c0ff0391bd6));
        vk.gamma_abc[52] = Pairing.G1Point(uint256(0x265c0e4b76642cb15eec95790fae49d30a190f5ed87330ff8b11726c4091b6aa), uint256(0x00e845210b909c19fc0417a403edec23cb2c938993453497048c3a3a112c99cd));
        vk.gamma_abc[53] = Pairing.G1Point(uint256(0x000456b02159c59b992f82e4bf20e9b6eb556636539ae65de22edbdc26e16f8f), uint256(0x2ae55517f51fa7b0478af3a38d91d1f408d3de83c5addc402f920fd270a19717));
        vk.gamma_abc[54] = Pairing.G1Point(uint256(0x22e9e4f7098cdf18377746c60f70fa670151c8b7fee71227f02d2f03417c8d34), uint256(0x02015470ea2558c5a3dbac96c7817da825b56abc8e8a63aa93b0722e415d1e92));
        vk.gamma_abc[55] = Pairing.G1Point(uint256(0x090ac605561f3bff72a4b15ee588f6c1e05e527f48884bd853e63b56d6176eae), uint256(0x2d1a84212ffa6f97b76cfea637ed89c86ee47dd87da4fd7a98d8bef78dc07e9c));
        vk.gamma_abc[56] = Pairing.G1Point(uint256(0x0ff4a470ab8fede68ec4f13472d757dead85a2acbfbb9209daedc88aec0f1e69), uint256(0x06adfac133a3c7b20b32314496d0ee468db97cae33445ad3eb28ec8ac8c736ec));
        vk.gamma_abc[57] = Pairing.G1Point(uint256(0x11ce5880084da68c150c442551a2d69230602864ec7e3373003bf9d9a196b3cb), uint256(0x2d74bc989052688a218f3b618769fa08c6029c4586588e56b0647e45cf4a1960));
        vk.gamma_abc[58] = Pairing.G1Point(uint256(0x0c19d7c1f530515a7da589da468861f920230f9a553b45afe5a0fc59e1aa6e2e), uint256(0x1c9144bf08c6803bbb5ccce39ded8e0414310a62e4d85e01860a59a9f6761deb));
        vk.gamma_abc[59] = Pairing.G1Point(uint256(0x20a46f259b1b2133aa133e59a06cda13c52bd78ae96d8e1ce752c62f85ae64d8), uint256(0x06abc886ddfa549d18f72f65fb66091c5277041d2f42ed0eb3c1c9f98dc7ced3));
        vk.gamma_abc[60] = Pairing.G1Point(uint256(0x04180d9fae338cd1dc36dfb4c114fd97066e9578914109f2d032db6198b7202c), uint256(0x13513c5684cfffb9f521a3709d0147e749a7be38bd65ff34a846a4632ae8556e));
        vk.gamma_abc[61] = Pairing.G1Point(uint256(0x0c29e22328afd69f5d370113855d0c149f7b54b1add544d48787dea546e6080e), uint256(0x2620d1e53a70d7f52e9d8b5a6bc17102c03bf19ec5ec9daeddd5e68aaa453d78));
        vk.gamma_abc[62] = Pairing.G1Point(uint256(0x2b5036581463961ac3ef718c280369b35dd94dd23d76001d6bbc4bef33f1046c), uint256(0x1f4233d1ed9ccf2939f1bd01b971687f5a6eccd09a004c47d0e70020fb39c2bd));
        vk.gamma_abc[63] = Pairing.G1Point(uint256(0x083795b94f0de3d26179dbf050eedafae64d0012fdad9d7ba4e58fee2d4e4551), uint256(0x085a9045dd13a299eadeda52359a768d5b6907833fde5a5b5a48df6393401a85));
        vk.gamma_abc[64] = Pairing.G1Point(uint256(0x2da0d2d01c0ad1a5923ed598683d5dadf1c2d004530bcf1808224ea93e522e7a), uint256(0x062367f87e494327b6626fd4d59e98428f63768602ecd4025ea12ee40fe2043d));
        vk.gamma_abc[65] = Pairing.G1Point(uint256(0x2625f68f80c448fb93d7689fbef10a3cd1a01159904f9a1583096cf9321f50dd), uint256(0x227b5c48e2c072f1a3f6f65ae25526ca25dfdef0e14f104514b73a915f6b4309));
        vk.gamma_abc[66] = Pairing.G1Point(uint256(0x09d9b3a9bad667ad0dafe8c4484b41ce139281f586733c1dfc20554107b92710), uint256(0x05ef340ec5ca287444d75d33ba829eb77cfb27775e7e22d0fc1e00ba6e17c0dd));
        vk.gamma_abc[67] = Pairing.G1Point(uint256(0x1df6aabd26d8d2bcb41833b662d767361bb71fe0d23b342343b2a91ca5889a27), uint256(0x09846ebdc377eaafbd847825744c303894c046b1ea012da2f3d6fad2373ef2c1));
        vk.gamma_abc[68] = Pairing.G1Point(uint256(0x02c33b0fb670b25ef327f923a21ec3e500c9cd26c3ffb5f2ad3fb5c85da26d70), uint256(0x08a33033479b9dba5575b736952d3a8d955db48a9204028333b5143318869c6b));
        vk.gamma_abc[69] = Pairing.G1Point(uint256(0x19472ee82c2ece899489c6cf536c765b06afad75d920b0058aef140a5c1e3587), uint256(0x2076829354d8c66e0fa680f92e910513ce28ed570cfc76c8c6155b7f3a1b7e88));
        vk.gamma_abc[70] = Pairing.G1Point(uint256(0x030f0bda1f4ddb54d470ff76acda9245399a005194d24761fea0b506b4b6eeb1), uint256(0x1ff5e540ac5dc38980805c7b2adee3a23110553cd21d11d2e0fbe7222cadcf02));
        vk.gamma_abc[71] = Pairing.G1Point(uint256(0x0a57980cf2f2be69e7ce1cd2040fe51b328034bdceabb64a40895dd87c1a3822), uint256(0x036c7f475d079163830e6c786190922323cd48b83e1ed1e7a131d87e9ca1fdf5));
        vk.gamma_abc[72] = Pairing.G1Point(uint256(0x10fe0ad1827c0dbdeb0b051a46d3f9df59fddc896458cd9c7fc4501c9f22d679), uint256(0x0134c0e9067c86be9fd62f812d395f04952abd3feb9481c9d6f3995970474283));
        vk.gamma_abc[73] = Pairing.G1Point(uint256(0x056edc7f3e7cda66f87c65fa3820202e1e087bc96d3279e9e5cab72674b2bb08), uint256(0x039a936487afe96c474f0302b94b3435960cf191d9bfd10d5724864a20c6644a));
        vk.gamma_abc[74] = Pairing.G1Point(uint256(0x1d7f36849d333b910e7f69ca66862ac59fc23d86566f75b6c4e968ee0e1a1d51), uint256(0x05d887c715888797fb875930de1649e96b6359d7c925567ea7584815a0ddcdba));
        vk.gamma_abc[75] = Pairing.G1Point(uint256(0x057aeaffe512095f69d5e94b17055f2cbf727cc8f9605a5b669c51f4727bfcdc), uint256(0x1650a9f211364bd06e61b3f7bc3aed45e86797de11fe108b07ac631e4bf421da));
        vk.gamma_abc[76] = Pairing.G1Point(uint256(0x240d5b1365f355a6b658fae4983cee1e5d674232fbdf4c2e8ae53c325c053641), uint256(0x29ed1e8f7c28448d39637a159671bd57222d1b808c0cf16753ab48934f1908ce));
        vk.gamma_abc[77] = Pairing.G1Point(uint256(0x21d373f419e470efed12bbd1e456b89f357ac82ccbfc07dce222cdbcc65e5383), uint256(0x163b1714162ff26f291be317063f18b858ff88acee623b33c02120461dba7f8f));
        vk.gamma_abc[78] = Pairing.G1Point(uint256(0x0975ad0a61fd847be001d2dea4c6c632bf8a65171a36f9604ea52823a5eb464a), uint256(0x1c0c7d9f4e809d44bc0bf95202f2c3393b881c46fcbfe60df97a9347d65cc230));
        vk.gamma_abc[79] = Pairing.G1Point(uint256(0x2851db101b60bc06776f7249e65bbc9475dedff794984910c47f67fcf52a4c26), uint256(0x266ebedb990a1162c309afdf70c441f224905ecec2aaba1aad9ae91006ead126));
        vk.gamma_abc[80] = Pairing.G1Point(uint256(0x2a1d0ba9e8e59466502ea9b9ae6a5802c2c143c860abc1972b2cbc4e457f8d9a), uint256(0x2186f170c01932c35159e7d4e5a125278d46100a013fd9fc21fd5be21eafe9e3));
        vk.gamma_abc[81] = Pairing.G1Point(uint256(0x04aba5122fd1420a05a8479b86fe331f07c28e5fa625b722340bd5b3df35b647), uint256(0x24d8c3f9b1c3a381fbd5b721a9ee80f882761e13f567e56e5ad58c91798259b6));
        vk.gamma_abc[82] = Pairing.G1Point(uint256(0x1a0b41c8f3e1dc85b346a9b31f0cc94d6475b045d4714eafa42455543c074866), uint256(0x036cc09cf8fe0ecc07e637aa5324abeeaa94b5ea9ac6a1c813762a2304e8ce87));
        vk.gamma_abc[83] = Pairing.G1Point(uint256(0x029c348b2294b1264be2464669f3c3af828acf10ba595f6e63de6b4606fca549), uint256(0x0e570a6d3bce6b07afca4b6c0fe2cb758c328f70e119a9dc49c170e65b5b40ec));
        vk.gamma_abc[84] = Pairing.G1Point(uint256(0x209cbc49e930a1ddab3f14766755525cdf1fa65f92ec4361e59361b2557ca08e), uint256(0x1e78313b61e9a065f150d4be1f24615292b09ecc32dfb7d5d4acf0f200c930f5));
        vk.gamma_abc[85] = Pairing.G1Point(uint256(0x24a25a0badbaa3b1faea3294463aaf16fbf8b03e5f9a1d8167aa175e6ceb972a), uint256(0x2903ca85391bc856fe84920e1c5ef7bcf1b218f5a7884b62c266b1fa7e80a6db));
    }
    function verify(uint[] memory input, Proof memory proof) internal view returns (uint) {
        uint256 snark_scalar_field = 21888242871839275222246405745257275088548364400416034343698204186575808495617;
        VerifyingKey memory vk = verifyingKey();
        require(input.length + 1 == vk.gamma_abc.length);
        // Compute the linear combination vk_x
        Pairing.G1Point memory vk_x = Pairing.G1Point(0, 0);
        for (uint i = 0; i < input.length; i++) {
            require(input[i] < snark_scalar_field);
            vk_x = Pairing.addition(vk_x, Pairing.scalar_mul(vk.gamma_abc[i + 1], input[i]));
        }
        vk_x = Pairing.addition(vk_x, vk.gamma_abc[0]);
        if(!Pairing.pairingProd4(
             proof.a, proof.b,
             Pairing.negate(vk_x), vk.gamma,
             Pairing.negate(proof.c), vk.delta,
             Pairing.negate(vk.alpha), vk.beta)) return 1;
        return 0;
    }
    function verifyTx(
            Proof memory proof, uint[85] memory input
        ) public view returns (bool r) {
        uint[] memory inputValues = new uint[](85);
        
        for(uint i = 0; i < input.length; i++){
            inputValues[i] = input[i];
        }
        if (verify(inputValues, proof) == 0) {
            return true;
        } else {
            return false;
        }
    }
    function testVerifyTx(
            Proof memory proof, uint[85] memory input
        ) public view returns (bool r) {
            r = true;
    }
}
