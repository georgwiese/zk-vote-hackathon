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
        vk.alpha = Pairing.G1Point(uint256(0x07d782143f9b65480bdd9361f0df95cd4941bc28c3aed5a509ac351e55b6e696), uint256(0x22c8fc6a8ed65264413a3cb0eaa2becbb1898b8df415133e860a73e7e7d3d7dd));
        vk.beta = Pairing.G2Point([uint256(0x0ef48a20270b625dd5e2c009bf4d18e5edd0b0c0ec9733d4a76f659573cce851), uint256(0x2268a82cb99dcca3a51970602061a9950848211a6fc8298704fe55bc20530c08)], [uint256(0x2aae42ab0996d488408b26129d00df5e2c39ff15832726fbdc641ff9144b1a0c), uint256(0x170af90193d289839b305afc751a620256fe0b70a77cd89f841c77da767f20d2)]);
        vk.gamma = Pairing.G2Point([uint256(0x112262f9c5627abefb9a0377bcc55c65ec18618f6e87dc575061b44125babb0c), uint256(0x1216f2467dcf7eb437fe80f2359a749632f6a27e4772c74a716f469ecd5ea2aa)], [uint256(0x0f70c6b054c0da41433db88e308bf943898bc747af4a970c5d601c94f391174c), uint256(0x1981639bb35215cf0bac83ef11f9daf1935de0f6ec1c93db946eca5f06e5d024)]);
        vk.delta = Pairing.G2Point([uint256(0x22c2bd5aa2ea7bee394f51e83f526e20064e310891d8fa916d9779b2e2b144a0), uint256(0x2a8c0cfb04af758f3b6d07bedb4972c9cf8751fcbd18ad8d3be70e26c677d993)], [uint256(0x09171d10518c6379216f91011aa02d68ea569f36ec0e8b6aef2500a480328c8a), uint256(0x08dc635f5accf5d051eecf2a7789f1a381b37db0469cb7dbca9faa507988157f)]);
        vk.gamma_abc = new Pairing.G1Point[](14);
        vk.gamma_abc[0] = Pairing.G1Point(uint256(0x05123892b2131de12559f7bc6d3191daaefa2b38092dcef08c52180f86286317), uint256(0x143a8575e1f8f9db9c25f1b19b80ce56e43b6a20c933fe94c6a3d6b9000e0e0b));
        vk.gamma_abc[1] = Pairing.G1Point(uint256(0x196b2d920317f1d221b07412f674422490adb1e7fcdcb97046d38e06f3d042c2), uint256(0x2da94c99765eef85396c34d644357ffff0051d289ffad5235070fc23192d23e7));
        vk.gamma_abc[2] = Pairing.G1Point(uint256(0x091cc7429e58eb511ef5f5bb79c3a77cfebc0b6edb9f127008f3ecc62fb8a3fe), uint256(0x1bbafcb87330a0bb1cb59ede80c5cbcc30b3265afc88d857349fca035d8e7a29));
        vk.gamma_abc[3] = Pairing.G1Point(uint256(0x2de52683096b6aa7ced6bb1fbeea219b71e26ee51eb9f1ac5d126f059309a6fb), uint256(0x210f4815a249aa4fd2d1107bb5a1d56ef03a35130e7b29441c1ec94bc3c005ad));
        vk.gamma_abc[4] = Pairing.G1Point(uint256(0x2a76a658657abd8ad50161f298381c5f34a873955d2bbda2ccaaa7ea739bd6b7), uint256(0x079985c9e9e7901d3a5b90e2a3c4e86ff86c95ff12e35b8335cfecd342f2ad38));
        vk.gamma_abc[5] = Pairing.G1Point(uint256(0x13c4646f40ea14c3efced714befa126d6906767da8a69ac85a97185f6868b38f), uint256(0x0e56826b8898166a65098284ea8cb8f18487a988cd047207413bff72a0ffbc82));
        vk.gamma_abc[6] = Pairing.G1Point(uint256(0x00e8e1d4d7539e9d6966c35b3481754c4e0428d611dad00fcf7efd66cb59dbab), uint256(0x17208717422e5f37e099a09cb693868caf686fd6c19540c846c56d4753fb32a6));
        vk.gamma_abc[7] = Pairing.G1Point(uint256(0x09a648cf2631797a99005ec95506456542047e485ee85f2dd82c7d8eb141137e), uint256(0x0d1117cc001113874fa166823201f5295f5c5c2962347029e90a97c17d5905c5));
        vk.gamma_abc[8] = Pairing.G1Point(uint256(0x0110efc847636b3bcaabbae3c4183dd462b74199af2a712705b7f2cb951ab539), uint256(0x041576061fc9f05cd5aade708a2a8b90d85c5fddebd88fc60c990bbc6cec7f16));
        vk.gamma_abc[9] = Pairing.G1Point(uint256(0x2d2d687dd5512929a5fefcc673de8199f07357b2f1af0009abcebf8816f0c919), uint256(0x22c9e1d9d1b0cc2150905e7d35702a5dd7d7987c3d5033e354ddd6d53924abd3));
        vk.gamma_abc[10] = Pairing.G1Point(uint256(0x0198d2ef64e3e7b5f67f73601dde03a27ebc9b359a4e80c8044ad31cd0f3eff4), uint256(0x2d5715dbe96526a81f953dd20470a7f39b75c38fc7d6c30e3d50f89595f6559f));
        vk.gamma_abc[11] = Pairing.G1Point(uint256(0x02cdf09043d31bcd62fe1ac6402f7af8e9e9bba65ef6b4fefa6c3b8cc2173b8c), uint256(0x133ef76033977ec2ca4f8f924b30255ea9665fe6eaf7d39698756fe7386fb9e9));
        vk.gamma_abc[12] = Pairing.G1Point(uint256(0x08c6f3a685deb499855264230882976f463046f426cab70969bfdc904a494d89), uint256(0x291f5e4215fcd3fb20126f25ee1e6d5e913e9bb46f7044c9ac63b20485d62402));
        vk.gamma_abc[13] = Pairing.G1Point(uint256(0x2c9f4be7b4514cc34a0d8749232c9947678a1a43c68718f9237bcc622206171d), uint256(0x2394f954538362451b3c08237a679438467f84a7fbeebf440c16aad6b7d9fc69));
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
            Proof memory proof, uint[13] memory input
        ) public view returns (bool r) {
        uint[] memory inputValues = new uint[](13);
        
        for(uint i = 0; i < input.length; i++){
            inputValues[i] = input[i];
        }
        if (verify(inputValues, proof) == 0) {
            return true;
        } else {
            return false;
        }
    }
}
