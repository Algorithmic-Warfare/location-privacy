
#[test_only]
module location_addr::location_tests;

use location_addr::proximity;

// IMPORTANT: This test uses Poseidon hash commitments (32 bytes)
// Commitment = Poseidon(x, y, z, blinding_factor)
// Public inputs = [commitment_hash (32 bytes), max_distance_squared (32 bytes)]

#[test]
fun test_e2e_proximity_verification() {
    use sui::test_scenario;

    let mut scenario = test_scenario::begin(@0x1);
    {
        let ctx = test_scenario::ctx(&mut scenario);
        proximity::init_for_testing(ctx);
    };

    // Initialize canonical verifying key
    scenario.next_tx(@0x1);
    {
        let server_cap = test_scenario::take_from_sender<proximity::ServerCap>(&scenario);
        let vk_bytes = vector[34u8, 114u8, 99u8, 209u8, 227u8, 104u8, 63u8, 7u8, 181u8, 6u8, 184u8, 240u8, 80u8, 69u8, 129u8, 104u8, 146u8, 26u8, 209u8, 150u8, 122u8, 180u8, 116u8, 242u8, 224u8, 10u8, 15u8, 209u8, 43u8, 213u8, 167u8, 0u8, 44u8, 194u8, 138u8, 172u8, 67u8, 149u8, 237u8, 45u8, 170u8, 184u8, 196u8, 3u8, 144u8, 166u8, 229u8, 108u8, 115u8, 214u8, 167u8, 45u8, 168u8, 65u8, 38u8, 83u8, 248u8, 24u8, 15u8, 247u8, 211u8, 73u8, 6u8, 1u8, 97u8, 152u8, 209u8, 206u8, 152u8, 174u8, 182u8, 23u8, 10u8, 0u8, 54u8, 124u8, 0u8, 197u8, 108u8, 155u8, 109u8, 196u8, 18u8, 214u8, 221u8, 145u8, 142u8, 126u8, 42u8, 93u8, 62u8, 200u8, 149u8, 247u8, 21u8, 151u8, 189u8, 161u8, 209u8, 113u8, 241u8, 151u8, 122u8, 9u8, 29u8, 80u8, 170u8, 44u8, 181u8, 50u8, 203u8, 207u8, 33u8, 64u8, 169u8, 44u8, 199u8, 242u8, 231u8, 59u8, 193u8, 150u8, 229u8, 216u8, 193u8, 236u8, 194u8, 12u8, 68u8, 168u8, 216u8, 54u8, 92u8, 81u8, 95u8, 254u8, 232u8, 75u8, 3u8, 235u8, 219u8, 141u8, 150u8, 169u8, 82u8, 141u8, 47u8, 59u8, 229u8, 97u8, 26u8, 194u8, 197u8, 85u8, 184u8, 192u8, 190u8, 160u8, 124u8, 162u8, 59u8, 242u8, 136u8, 193u8, 115u8, 3u8, 8u8, 91u8, 64u8, 42u8, 65u8, 187u8, 74u8, 40u8, 22u8, 20u8, 93u8, 30u8, 174u8, 235u8, 61u8, 19u8, 199u8, 3u8, 129u8, 137u8, 173u8, 151u8, 116u8, 234u8, 31u8, 15u8, 247u8, 212u8, 133u8, 77u8, 45u8, 82u8, 171u8, 255u8, 168u8, 119u8, 10u8, 10u8, 106u8, 39u8, 135u8, 110u8, 165u8, 171u8, 176u8, 234u8, 197u8, 5u8, 14u8, 94u8, 109u8, 180u8, 149u8, 186u8, 196u8, 7u8, 249u8, 172u8, 3u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 251u8, 27u8, 86u8, 50u8, 232u8, 158u8, 244u8, 235u8, 201u8, 32u8, 194u8, 147u8, 227u8, 62u8, 171u8, 64u8, 227u8, 21u8, 199u8, 103u8, 187u8, 73u8, 74u8, 221u8, 191u8, 80u8, 189u8, 98u8, 143u8, 218u8, 127u8, 22u8, 39u8, 94u8, 34u8, 59u8, 47u8, 70u8, 210u8, 233u8, 17u8, 18u8, 5u8, 200u8, 27u8, 165u8, 140u8, 26u8, 145u8, 67u8, 156u8, 161u8, 81u8, 4u8, 49u8, 166u8, 171u8, 222u8, 0u8, 128u8, 238u8, 40u8, 161u8, 8u8, 203u8, 99u8, 113u8, 178u8, 136u8, 9u8, 164u8, 221u8, 156u8, 185u8, 34u8, 37u8, 34u8, 140u8, 96u8, 149u8, 167u8, 216u8, 240u8, 214u8, 127u8, 246u8, 113u8, 69u8, 107u8, 188u8, 252u8, 139u8, 241u8, 188u8, 3u8, 133u8]; // Canonical verifying key (328 bytes)
        
        let ctx = test_scenario::ctx(&mut scenario);
        proximity::init_verifying_key(&server_cap, vk_bytes, ctx);
        
        test_scenario::return_to_sender(&scenario, server_cap);
    };

    // Create commitment (Poseidon hash - 32 bytes)
    scenario.next_tx(@0x1);
    {
        let server_cap = test_scenario::take_from_sender<proximity::ServerCap>(&scenario);
        let commitment_bytes = vector[145u8, 56u8, 219u8, 216u8, 111u8, 212u8, 2u8, 176u8, 162u8, 240u8, 40u8, 215u8, 255u8, 202u8, 30u8, 51u8, 141u8, 163u8, 230u8, 215u8, 225u8, 5u8, 26u8, 24u8, 171u8, 237u8, 7u8, 24u8, 34u8, 97u8, 255u8, 46u8]; // Poseidon hash (32 bytes)
        let owner = @0x2;
        
        let ctx = test_scenario::ctx(&mut scenario);
        proximity::create_commitment(&server_cap, commitment_bytes, owner, ctx);
        
        test_scenario::return_to_sender(&scenario, server_cap);
    };

    // Verify proximity proof
    scenario.next_tx(@0x2);
    {
        let mut commitment = test_scenario::take_shared<proximity::LocationCommitment>(&scenario);
        let verifying_key = test_scenario::take_shared<proximity::VerifyingKey>(&scenario);
        let proof_bytes = vector[83u8, 139u8, 54u8, 189u8, 134u8, 135u8, 132u8, 123u8, 174u8, 119u8, 33u8, 62u8, 211u8, 222u8, 132u8, 164u8, 33u8, 146u8, 35u8, 105u8, 2u8, 65u8, 81u8, 242u8, 228u8, 161u8, 150u8, 232u8, 79u8, 65u8, 153u8, 33u8, 182u8, 138u8, 141u8, 27u8, 189u8, 229u8, 47u8, 153u8, 206u8, 17u8, 87u8, 101u8, 67u8, 16u8, 185u8, 38u8, 14u8, 158u8, 123u8, 26u8, 199u8, 238u8, 200u8, 132u8, 142u8, 232u8, 136u8, 190u8, 60u8, 34u8, 79u8, 32u8, 180u8, 147u8, 237u8, 35u8, 126u8, 66u8, 209u8, 134u8, 9u8, 0u8, 229u8, 37u8, 8u8, 40u8, 35u8, 29u8, 97u8, 123u8, 104u8, 52u8, 113u8, 255u8, 11u8, 156u8, 197u8, 58u8, 127u8, 29u8, 28u8, 189u8, 1u8, 21u8, 92u8, 44u8, 211u8, 109u8, 42u8, 239u8, 208u8, 132u8, 96u8, 35u8, 215u8, 147u8, 138u8, 121u8, 170u8, 23u8, 43u8, 246u8, 84u8, 207u8, 230u8, 251u8, 234u8, 37u8, 246u8, 99u8, 253u8, 19u8, 34u8, 176u8, 95u8, 168u8];
        let public_inputs = vector[145u8, 56u8, 219u8, 216u8, 111u8, 212u8, 2u8, 176u8, 162u8, 240u8, 40u8, 215u8, 255u8, 202u8, 30u8, 51u8, 141u8, 163u8, 230u8, 215u8, 225u8, 5u8, 26u8, 24u8, 171u8, 237u8, 7u8, 24u8, 34u8, 97u8, 255u8, 46u8, 0u8, 225u8, 245u8, 5u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8]; // [commitment_hash, max_distance_squared] (64 bytes total)
        
        let ctx = test_scenario::ctx(&mut scenario);
        proximity::verify_proximity_proof(&mut commitment, &verifying_key, proof_bytes, public_inputs, ctx);
        
        // Verify nonce was incremented
        let nonce = proximity::get_nonce(&commitment);
        assert!(nonce == 1, 0);
        
        test_scenario::return_shared(commitment);
        test_scenario::return_shared(verifying_key);
    };

    test_scenario::end(scenario);
}

#[test]
#[expected_failure]
fun test_corrupted_proof_fails() {
    use sui::test_scenario;

    let mut scenario = test_scenario::begin(@0x1);
    {
        let ctx = test_scenario::ctx(&mut scenario);
        proximity::init_for_testing(ctx);
    };

    // Initialize canonical verifying key
    scenario.next_tx(@0x1);
    {
        let server_cap = test_scenario::take_from_sender<proximity::ServerCap>(&scenario);
        let vk_bytes = vector[34u8, 114u8, 99u8, 209u8, 227u8, 104u8, 63u8, 7u8, 181u8, 6u8, 184u8, 240u8, 80u8, 69u8, 129u8, 104u8, 146u8, 26u8, 209u8, 150u8, 122u8, 180u8, 116u8, 242u8, 224u8, 10u8, 15u8, 209u8, 43u8, 213u8, 167u8, 0u8, 44u8, 194u8, 138u8, 172u8, 67u8, 149u8, 237u8, 45u8, 170u8, 184u8, 196u8, 3u8, 144u8, 166u8, 229u8, 108u8, 115u8, 214u8, 167u8, 45u8, 168u8, 65u8, 38u8, 83u8, 248u8, 24u8, 15u8, 247u8, 211u8, 73u8, 6u8, 1u8, 97u8, 152u8, 209u8, 206u8, 152u8, 174u8, 182u8, 23u8, 10u8, 0u8, 54u8, 124u8, 0u8, 197u8, 108u8, 155u8, 109u8, 196u8, 18u8, 214u8, 221u8, 145u8, 142u8, 126u8, 42u8, 93u8, 62u8, 200u8, 149u8, 247u8, 21u8, 151u8, 189u8, 161u8, 209u8, 113u8, 241u8, 151u8, 122u8, 9u8, 29u8, 80u8, 170u8, 44u8, 181u8, 50u8, 203u8, 207u8, 33u8, 64u8, 169u8, 44u8, 199u8, 242u8, 231u8, 59u8, 193u8, 150u8, 229u8, 216u8, 193u8, 236u8, 194u8, 12u8, 68u8, 168u8, 216u8, 54u8, 92u8, 81u8, 95u8, 254u8, 232u8, 75u8, 3u8, 235u8, 219u8, 141u8, 150u8, 169u8, 82u8, 141u8, 47u8, 59u8, 229u8, 97u8, 26u8, 194u8, 197u8, 85u8, 184u8, 192u8, 190u8, 160u8, 124u8, 162u8, 59u8, 242u8, 136u8, 193u8, 115u8, 3u8, 8u8, 91u8, 64u8, 42u8, 65u8, 187u8, 74u8, 40u8, 22u8, 20u8, 93u8, 30u8, 174u8, 235u8, 61u8, 19u8, 199u8, 3u8, 129u8, 137u8, 173u8, 151u8, 116u8, 234u8, 31u8, 15u8, 247u8, 212u8, 133u8, 77u8, 45u8, 82u8, 171u8, 255u8, 168u8, 119u8, 10u8, 10u8, 106u8, 39u8, 135u8, 110u8, 165u8, 171u8, 176u8, 234u8, 197u8, 5u8, 14u8, 94u8, 109u8, 180u8, 149u8, 186u8, 196u8, 7u8, 249u8, 172u8, 3u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 251u8, 27u8, 86u8, 50u8, 232u8, 158u8, 244u8, 235u8, 201u8, 32u8, 194u8, 147u8, 227u8, 62u8, 171u8, 64u8, 227u8, 21u8, 199u8, 103u8, 187u8, 73u8, 74u8, 221u8, 191u8, 80u8, 189u8, 98u8, 143u8, 218u8, 127u8, 22u8, 39u8, 94u8, 34u8, 59u8, 47u8, 70u8, 210u8, 233u8, 17u8, 18u8, 5u8, 200u8, 27u8, 165u8, 140u8, 26u8, 145u8, 67u8, 156u8, 161u8, 81u8, 4u8, 49u8, 166u8, 171u8, 222u8, 0u8, 128u8, 238u8, 40u8, 161u8, 8u8, 203u8, 99u8, 113u8, 178u8, 136u8, 9u8, 164u8, 221u8, 156u8, 185u8, 34u8, 37u8, 34u8, 140u8, 96u8, 149u8, 167u8, 216u8, 240u8, 214u8, 127u8, 246u8, 113u8, 69u8, 107u8, 188u8, 252u8, 139u8, 241u8, 188u8, 3u8, 133u8];
        
        let ctx = test_scenario::ctx(&mut scenario);
        proximity::init_verifying_key(&server_cap, vk_bytes, ctx);
        
        test_scenario::return_to_sender(&scenario, server_cap);
    };

    // Create commitment
    scenario.next_tx(@0x1);
    {
        let server_cap = test_scenario::take_from_sender<proximity::ServerCap>(&scenario);
        let commitment_bytes = vector[145u8, 56u8, 219u8, 216u8, 111u8, 212u8, 2u8, 176u8, 162u8, 240u8, 40u8, 215u8, 255u8, 202u8, 30u8, 51u8, 141u8, 163u8, 230u8, 215u8, 225u8, 5u8, 26u8, 24u8, 171u8, 237u8, 7u8, 24u8, 34u8, 97u8, 255u8, 46u8];
        let owner = @0x2;
        
        let ctx = test_scenario::ctx(&mut scenario);
        proximity::create_commitment(&server_cap, commitment_bytes, owner, ctx);
        
        test_scenario::return_to_sender(&scenario, server_cap);
    };

    // Try to verify with corrupted proof - should fail
    scenario.next_tx(@0x2);
    {
        let mut commitment = test_scenario::take_shared<proximity::LocationCommitment>(&scenario);
        let verifying_key = test_scenario::take_shared<proximity::VerifyingKey>(&scenario);
        let proof_bytes = vector[83u8, 139u8, 54u8, 189u8, 134u8, 135u8, 132u8, 123u8, 174u8, 119u8, 222u8, 62u8, 211u8, 222u8, 132u8, 164u8, 33u8, 146u8, 35u8, 105u8, 2u8, 65u8, 81u8, 242u8, 228u8, 161u8, 150u8, 232u8, 79u8, 65u8, 153u8, 33u8, 182u8, 138u8, 141u8, 27u8, 189u8, 229u8, 47u8, 153u8, 206u8, 17u8, 87u8, 101u8, 67u8, 16u8, 185u8, 38u8, 14u8, 158u8, 123u8, 26u8, 199u8, 238u8, 200u8, 132u8, 142u8, 232u8, 136u8, 190u8, 60u8, 34u8, 79u8, 32u8, 180u8, 147u8, 237u8, 35u8, 126u8, 66u8, 209u8, 134u8, 9u8, 0u8, 229u8, 37u8, 8u8, 40u8, 35u8, 29u8, 97u8, 123u8, 104u8, 52u8, 113u8, 255u8, 11u8, 156u8, 197u8, 58u8, 127u8, 29u8, 28u8, 189u8, 1u8, 21u8, 92u8, 44u8, 211u8, 109u8, 42u8, 239u8, 208u8, 132u8, 96u8, 35u8, 215u8, 147u8, 138u8, 121u8, 170u8, 23u8, 43u8, 246u8, 84u8, 207u8, 230u8, 251u8, 234u8, 37u8, 246u8, 99u8, 253u8, 19u8, 34u8, 176u8, 95u8, 168u8]; // Corrupted proof bytes
        let public_inputs = vector[145u8, 56u8, 219u8, 216u8, 111u8, 212u8, 2u8, 176u8, 162u8, 240u8, 40u8, 215u8, 255u8, 202u8, 30u8, 51u8, 141u8, 163u8, 230u8, 215u8, 225u8, 5u8, 26u8, 24u8, 171u8, 237u8, 7u8, 24u8, 34u8, 97u8, 255u8, 46u8, 0u8, 225u8, 245u8, 5u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8];
        
        let ctx = test_scenario::ctx(&mut scenario);
        // This should fail because the proof is corrupted
        proximity::verify_proximity_proof(&mut commitment, &verifying_key, proof_bytes, public_inputs, ctx);
        
        test_scenario::return_shared(commitment);
        test_scenario::return_shared(verifying_key);
    };

    test_scenario::end(scenario);
}

#[test]
#[expected_failure(abort_code = 4)]
fun test_wrong_verification_key_fails() {
    use sui::test_scenario;

    let mut scenario = test_scenario::begin(@0x1);
    {
        let ctx = test_scenario::ctx(&mut scenario);
        proximity::init_for_testing(ctx);
    };

    // Initialize WRONG canonical verifying key
    scenario.next_tx(@0x1);
    {
        let server_cap = test_scenario::take_from_sender<proximity::ServerCap>(&scenario);
        let wrong_vk_bytes = vector[189u8, 59u8, 131u8, 199u8, 148u8, 76u8, 33u8, 143u8, 35u8, 13u8, 189u8, 222u8, 188u8, 50u8, 206u8, 218u8, 46u8, 239u8, 54u8, 60u8, 157u8, 206u8, 68u8, 230u8, 150u8, 91u8, 126u8, 192u8, 184u8, 200u8, 191u8, 18u8, 65u8, 180u8, 125u8, 65u8, 85u8, 155u8, 24u8, 254u8, 157u8, 182u8, 83u8, 226u8, 237u8, 232u8, 97u8, 55u8, 255u8, 135u8, 141u8, 120u8, 127u8, 37u8, 158u8, 94u8, 135u8, 254u8, 24u8, 225u8, 180u8, 34u8, 110u8, 19u8, 120u8, 255u8, 201u8, 76u8, 235u8, 41u8, 135u8, 154u8, 152u8, 215u8, 82u8, 240u8, 73u8, 150u8, 42u8, 81u8, 95u8, 38u8, 254u8, 19u8, 71u8, 179u8, 106u8, 203u8, 23u8, 190u8, 171u8, 157u8, 121u8, 166u8, 42u8, 151u8, 78u8, 63u8, 178u8, 20u8, 232u8, 96u8, 147u8, 32u8, 38u8, 6u8, 117u8, 62u8, 101u8, 102u8, 184u8, 59u8, 211u8, 165u8, 28u8, 192u8, 240u8, 251u8, 233u8, 102u8, 244u8, 159u8, 14u8, 161u8, 191u8, 199u8, 17u8, 11u8, 67u8, 74u8, 74u8, 155u8, 206u8, 80u8, 227u8, 226u8, 168u8, 92u8, 235u8, 130u8, 13u8, 189u8, 206u8, 106u8, 110u8, 69u8, 223u8, 251u8, 100u8, 37u8, 33u8, 224u8, 204u8, 109u8, 213u8, 126u8, 171u8, 159u8, 33u8, 38u8, 146u8, 25u8, 92u8, 133u8, 130u8, 187u8, 8u8, 133u8, 132u8, 172u8, 123u8, 202u8, 237u8, 58u8, 68u8, 242u8, 3u8, 203u8, 155u8, 45u8, 124u8, 168u8, 183u8, 61u8, 81u8, 188u8, 255u8, 233u8, 78u8, 150u8, 177u8, 37u8, 164u8, 249u8, 1u8, 175u8, 155u8, 234u8, 137u8, 42u8, 172u8, 221u8, 6u8, 21u8, 128u8, 89u8, 187u8, 199u8, 27u8, 231u8, 69u8, 175u8, 150u8, 34u8, 37u8, 145u8, 77u8, 106u8, 240u8, 208u8, 121u8, 202u8, 200u8, 162u8, 3u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 106u8, 190u8, 170u8, 108u8, 188u8, 165u8, 95u8, 154u8, 85u8, 78u8, 72u8, 176u8, 10u8, 106u8, 245u8, 203u8, 117u8, 104u8, 48u8, 4u8, 161u8, 229u8, 19u8, 202u8, 48u8, 82u8, 242u8, 30u8, 221u8, 33u8, 149u8, 144u8, 232u8, 29u8, 39u8, 215u8, 149u8, 56u8, 88u8, 173u8, 93u8, 131u8, 80u8, 47u8, 9u8, 229u8, 86u8, 80u8, 62u8, 237u8, 229u8, 120u8, 168u8, 251u8, 155u8, 28u8, 49u8, 144u8, 148u8, 87u8, 76u8, 47u8, 218u8, 41u8, 99u8, 214u8, 73u8, 73u8, 56u8, 204u8, 91u8, 85u8, 176u8, 121u8, 93u8, 147u8, 113u8, 75u8, 91u8, 3u8, 169u8, 64u8, 130u8, 103u8, 87u8, 61u8, 218u8, 159u8, 118u8, 111u8, 225u8, 129u8, 227u8, 195u8, 40u8, 163u8]; // Wrong VK bytes (from different trusted setup)
        
        let ctx = test_scenario::ctx(&mut scenario);
        proximity::init_verifying_key(&server_cap, wrong_vk_bytes, ctx);
        
        test_scenario::return_to_sender(&scenario, server_cap);
    };

    // Create commitment
    scenario.next_tx(@0x1);
    {
        let server_cap = test_scenario::take_from_sender<proximity::ServerCap>(&scenario);
        let commitment_bytes = vector[145u8, 56u8, 219u8, 216u8, 111u8, 212u8, 2u8, 176u8, 162u8, 240u8, 40u8, 215u8, 255u8, 202u8, 30u8, 51u8, 141u8, 163u8, 230u8, 215u8, 225u8, 5u8, 26u8, 24u8, 171u8, 237u8, 7u8, 24u8, 34u8, 97u8, 255u8, 46u8];
        let owner = @0x2;
        
        let ctx = test_scenario::ctx(&mut scenario);
        proximity::create_commitment(&server_cap, commitment_bytes, owner, ctx);
        
        test_scenario::return_to_sender(&scenario, server_cap);
    };

    // Try to verify with proof generated for different VK - should fail
    scenario.next_tx(@0x2);
    {
        let mut commitment = test_scenario::take_shared<proximity::LocationCommitment>(&scenario);
        let verifying_key = test_scenario::take_shared<proximity::VerifyingKey>(&scenario);
        let proof_bytes = vector[83u8, 139u8, 54u8, 189u8, 134u8, 135u8, 132u8, 123u8, 174u8, 119u8, 33u8, 62u8, 211u8, 222u8, 132u8, 164u8, 33u8, 146u8, 35u8, 105u8, 2u8, 65u8, 81u8, 242u8, 228u8, 161u8, 150u8, 232u8, 79u8, 65u8, 153u8, 33u8, 182u8, 138u8, 141u8, 27u8, 189u8, 229u8, 47u8, 153u8, 206u8, 17u8, 87u8, 101u8, 67u8, 16u8, 185u8, 38u8, 14u8, 158u8, 123u8, 26u8, 199u8, 238u8, 200u8, 132u8, 142u8, 232u8, 136u8, 190u8, 60u8, 34u8, 79u8, 32u8, 180u8, 147u8, 237u8, 35u8, 126u8, 66u8, 209u8, 134u8, 9u8, 0u8, 229u8, 37u8, 8u8, 40u8, 35u8, 29u8, 97u8, 123u8, 104u8, 52u8, 113u8, 255u8, 11u8, 156u8, 197u8, 58u8, 127u8, 29u8, 28u8, 189u8, 1u8, 21u8, 92u8, 44u8, 211u8, 109u8, 42u8, 239u8, 208u8, 132u8, 96u8, 35u8, 215u8, 147u8, 138u8, 121u8, 170u8, 23u8, 43u8, 246u8, 84u8, 207u8, 230u8, 251u8, 234u8, 37u8, 246u8, 99u8, 253u8, 19u8, 34u8, 176u8, 95u8, 168u8]; // Proof generated with correct VK
        let public_inputs = vector[145u8, 56u8, 219u8, 216u8, 111u8, 212u8, 2u8, 176u8, 162u8, 240u8, 40u8, 215u8, 255u8, 202u8, 30u8, 51u8, 141u8, 163u8, 230u8, 215u8, 225u8, 5u8, 26u8, 24u8, 171u8, 237u8, 7u8, 24u8, 34u8, 97u8, 255u8, 46u8, 0u8, 225u8, 245u8, 5u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8];
        
        let ctx = test_scenario::ctx(&mut scenario);
        // This should fail because the proof was generated with a different VK
        proximity::verify_proximity_proof(&mut commitment, &verifying_key, proof_bytes, public_inputs, ctx);
        
        test_scenario::return_shared(commitment);
        test_scenario::return_shared(verifying_key);
    };

    test_scenario::end(scenario);
}

#[test]
#[expected_failure]
fun test_wrong_public_inputs_fails() {
    use sui::test_scenario;

    let mut scenario = test_scenario::begin(@0x1);
    {
        let ctx = test_scenario::ctx(&mut scenario);
        proximity::init_for_testing(ctx);
    };

    // Initialize canonical verifying key
    scenario.next_tx(@0x1);
    {
        let server_cap = test_scenario::take_from_sender<proximity::ServerCap>(&scenario);
        let vk_bytes = vector[34u8, 114u8, 99u8, 209u8, 227u8, 104u8, 63u8, 7u8, 181u8, 6u8, 184u8, 240u8, 80u8, 69u8, 129u8, 104u8, 146u8, 26u8, 209u8, 150u8, 122u8, 180u8, 116u8, 242u8, 224u8, 10u8, 15u8, 209u8, 43u8, 213u8, 167u8, 0u8, 44u8, 194u8, 138u8, 172u8, 67u8, 149u8, 237u8, 45u8, 170u8, 184u8, 196u8, 3u8, 144u8, 166u8, 229u8, 108u8, 115u8, 214u8, 167u8, 45u8, 168u8, 65u8, 38u8, 83u8, 248u8, 24u8, 15u8, 247u8, 211u8, 73u8, 6u8, 1u8, 97u8, 152u8, 209u8, 206u8, 152u8, 174u8, 182u8, 23u8, 10u8, 0u8, 54u8, 124u8, 0u8, 197u8, 108u8, 155u8, 109u8, 196u8, 18u8, 214u8, 221u8, 145u8, 142u8, 126u8, 42u8, 93u8, 62u8, 200u8, 149u8, 247u8, 21u8, 151u8, 189u8, 161u8, 209u8, 113u8, 241u8, 151u8, 122u8, 9u8, 29u8, 80u8, 170u8, 44u8, 181u8, 50u8, 203u8, 207u8, 33u8, 64u8, 169u8, 44u8, 199u8, 242u8, 231u8, 59u8, 193u8, 150u8, 229u8, 216u8, 193u8, 236u8, 194u8, 12u8, 68u8, 168u8, 216u8, 54u8, 92u8, 81u8, 95u8, 254u8, 232u8, 75u8, 3u8, 235u8, 219u8, 141u8, 150u8, 169u8, 82u8, 141u8, 47u8, 59u8, 229u8, 97u8, 26u8, 194u8, 197u8, 85u8, 184u8, 192u8, 190u8, 160u8, 124u8, 162u8, 59u8, 242u8, 136u8, 193u8, 115u8, 3u8, 8u8, 91u8, 64u8, 42u8, 65u8, 187u8, 74u8, 40u8, 22u8, 20u8, 93u8, 30u8, 174u8, 235u8, 61u8, 19u8, 199u8, 3u8, 129u8, 137u8, 173u8, 151u8, 116u8, 234u8, 31u8, 15u8, 247u8, 212u8, 133u8, 77u8, 45u8, 82u8, 171u8, 255u8, 168u8, 119u8, 10u8, 10u8, 106u8, 39u8, 135u8, 110u8, 165u8, 171u8, 176u8, 234u8, 197u8, 5u8, 14u8, 94u8, 109u8, 180u8, 149u8, 186u8, 196u8, 7u8, 249u8, 172u8, 3u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 251u8, 27u8, 86u8, 50u8, 232u8, 158u8, 244u8, 235u8, 201u8, 32u8, 194u8, 147u8, 227u8, 62u8, 171u8, 64u8, 227u8, 21u8, 199u8, 103u8, 187u8, 73u8, 74u8, 221u8, 191u8, 80u8, 189u8, 98u8, 143u8, 218u8, 127u8, 22u8, 39u8, 94u8, 34u8, 59u8, 47u8, 70u8, 210u8, 233u8, 17u8, 18u8, 5u8, 200u8, 27u8, 165u8, 140u8, 26u8, 145u8, 67u8, 156u8, 161u8, 81u8, 4u8, 49u8, 166u8, 171u8, 222u8, 0u8, 128u8, 238u8, 40u8, 161u8, 8u8, 203u8, 99u8, 113u8, 178u8, 136u8, 9u8, 164u8, 221u8, 156u8, 185u8, 34u8, 37u8, 34u8, 140u8, 96u8, 149u8, 167u8, 216u8, 240u8, 214u8, 127u8, 246u8, 113u8, 69u8, 107u8, 188u8, 252u8, 139u8, 241u8, 188u8, 3u8, 133u8];
        
        let ctx = test_scenario::ctx(&mut scenario);
        proximity::init_verifying_key(&server_cap, vk_bytes, ctx);
        
        test_scenario::return_to_sender(&scenario, server_cap);
    };

    // Create commitment
    scenario.next_tx(@0x1);
    {
        let server_cap = test_scenario::take_from_sender<proximity::ServerCap>(&scenario);
        let commitment_bytes = vector[145u8, 56u8, 219u8, 216u8, 111u8, 212u8, 2u8, 176u8, 162u8, 240u8, 40u8, 215u8, 255u8, 202u8, 30u8, 51u8, 141u8, 163u8, 230u8, 215u8, 225u8, 5u8, 26u8, 24u8, 171u8, 237u8, 7u8, 24u8, 34u8, 97u8, 255u8, 46u8];
        let owner = @0x2;
        
        let ctx = test_scenario::ctx(&mut scenario);
        proximity::create_commitment(&server_cap, commitment_bytes, owner, ctx);
        
        test_scenario::return_to_sender(&scenario, server_cap);
    };

    // Try to verify with wrong public inputs - should fail
    scenario.next_tx(@0x2);
    {
        let mut commitment = test_scenario::take_shared<proximity::LocationCommitment>(&scenario);
        let verifying_key = test_scenario::take_shared<proximity::VerifyingKey>(&scenario);
        let proof_bytes = vector[83u8, 139u8, 54u8, 189u8, 134u8, 135u8, 132u8, 123u8, 174u8, 119u8, 33u8, 62u8, 211u8, 222u8, 132u8, 164u8, 33u8, 146u8, 35u8, 105u8, 2u8, 65u8, 81u8, 242u8, 228u8, 161u8, 150u8, 232u8, 79u8, 65u8, 153u8, 33u8, 182u8, 138u8, 141u8, 27u8, 189u8, 229u8, 47u8, 153u8, 206u8, 17u8, 87u8, 101u8, 67u8, 16u8, 185u8, 38u8, 14u8, 158u8, 123u8, 26u8, 199u8, 238u8, 200u8, 132u8, 142u8, 232u8, 136u8, 190u8, 60u8, 34u8, 79u8, 32u8, 180u8, 147u8, 237u8, 35u8, 126u8, 66u8, 209u8, 134u8, 9u8, 0u8, 229u8, 37u8, 8u8, 40u8, 35u8, 29u8, 97u8, 123u8, 104u8, 52u8, 113u8, 255u8, 11u8, 156u8, 197u8, 58u8, 127u8, 29u8, 28u8, 189u8, 1u8, 21u8, 92u8, 44u8, 211u8, 109u8, 42u8, 239u8, 208u8, 132u8, 96u8, 35u8, 215u8, 147u8, 138u8, 121u8, 170u8, 23u8, 43u8, 246u8, 84u8, 207u8, 230u8, 251u8, 234u8, 37u8, 246u8, 99u8, 253u8, 19u8, 34u8, 176u8, 95u8, 168u8];
        let public_inputs = vector[145u8, 56u8, 219u8, 216u8, 111u8, 212u8, 2u8, 176u8, 162u8, 240u8, 40u8, 215u8, 255u8, 202u8, 30u8, 51u8, 114u8, 163u8, 230u8, 215u8, 225u8, 5u8, 26u8, 24u8, 171u8, 237u8, 7u8, 24u8, 34u8, 97u8, 255u8, 46u8, 0u8, 225u8, 245u8, 5u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8]; // Wrong public inputs
        
        let ctx = test_scenario::ctx(&mut scenario);
        // This should fail because the public inputs don't match the proof
        proximity::verify_proximity_proof(&mut commitment, &verifying_key, proof_bytes, public_inputs, ctx);
        
        test_scenario::return_shared(commitment);
        test_scenario::return_shared(verifying_key);
    };

    test_scenario::end(scenario);
}

#[test]
fun test_user_within_10km_succeeds() {
    use sui::test_scenario;

    let mut scenario = test_scenario::begin(@0x1);
    {
        let ctx = test_scenario::ctx(&mut scenario);
        proximity::init_for_testing(ctx);
    };

    // Initialize canonical verifying key
    scenario.next_tx(@0x1);
    {
        let server_cap = test_scenario::take_from_sender<proximity::ServerCap>(&scenario);
        let vk_bytes = vector[34u8, 114u8, 99u8, 209u8, 227u8, 104u8, 63u8, 7u8, 181u8, 6u8, 184u8, 240u8, 80u8, 69u8, 129u8, 104u8, 146u8, 26u8, 209u8, 150u8, 122u8, 180u8, 116u8, 242u8, 224u8, 10u8, 15u8, 209u8, 43u8, 213u8, 167u8, 0u8, 44u8, 194u8, 138u8, 172u8, 67u8, 149u8, 237u8, 45u8, 170u8, 184u8, 196u8, 3u8, 144u8, 166u8, 229u8, 108u8, 115u8, 214u8, 167u8, 45u8, 168u8, 65u8, 38u8, 83u8, 248u8, 24u8, 15u8, 247u8, 211u8, 73u8, 6u8, 1u8, 97u8, 152u8, 209u8, 206u8, 152u8, 174u8, 182u8, 23u8, 10u8, 0u8, 54u8, 124u8, 0u8, 197u8, 108u8, 155u8, 109u8, 196u8, 18u8, 214u8, 221u8, 145u8, 142u8, 126u8, 42u8, 93u8, 62u8, 200u8, 149u8, 247u8, 21u8, 151u8, 189u8, 161u8, 209u8, 113u8, 241u8, 151u8, 122u8, 9u8, 29u8, 80u8, 170u8, 44u8, 181u8, 50u8, 203u8, 207u8, 33u8, 64u8, 169u8, 44u8, 199u8, 242u8, 231u8, 59u8, 193u8, 150u8, 229u8, 216u8, 193u8, 236u8, 194u8, 12u8, 68u8, 168u8, 216u8, 54u8, 92u8, 81u8, 95u8, 254u8, 232u8, 75u8, 3u8, 235u8, 219u8, 141u8, 150u8, 169u8, 82u8, 141u8, 47u8, 59u8, 229u8, 97u8, 26u8, 194u8, 197u8, 85u8, 184u8, 192u8, 190u8, 160u8, 124u8, 162u8, 59u8, 242u8, 136u8, 193u8, 115u8, 3u8, 8u8, 91u8, 64u8, 42u8, 65u8, 187u8, 74u8, 40u8, 22u8, 20u8, 93u8, 30u8, 174u8, 235u8, 61u8, 19u8, 199u8, 3u8, 129u8, 137u8, 173u8, 151u8, 116u8, 234u8, 31u8, 15u8, 247u8, 212u8, 133u8, 77u8, 45u8, 82u8, 171u8, 255u8, 168u8, 119u8, 10u8, 10u8, 106u8, 39u8, 135u8, 110u8, 165u8, 171u8, 176u8, 234u8, 197u8, 5u8, 14u8, 94u8, 109u8, 180u8, 149u8, 186u8, 196u8, 7u8, 249u8, 172u8, 3u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 251u8, 27u8, 86u8, 50u8, 232u8, 158u8, 244u8, 235u8, 201u8, 32u8, 194u8, 147u8, 227u8, 62u8, 171u8, 64u8, 227u8, 21u8, 199u8, 103u8, 187u8, 73u8, 74u8, 221u8, 191u8, 80u8, 189u8, 98u8, 143u8, 218u8, 127u8, 22u8, 39u8, 94u8, 34u8, 59u8, 47u8, 70u8, 210u8, 233u8, 17u8, 18u8, 5u8, 200u8, 27u8, 165u8, 140u8, 26u8, 145u8, 67u8, 156u8, 161u8, 81u8, 4u8, 49u8, 166u8, 171u8, 222u8, 0u8, 128u8, 238u8, 40u8, 161u8, 8u8, 203u8, 99u8, 113u8, 178u8, 136u8, 9u8, 164u8, 221u8, 156u8, 185u8, 34u8, 37u8, 34u8, 140u8, 96u8, 149u8, 167u8, 216u8, 240u8, 214u8, 127u8, 246u8, 113u8, 69u8, 107u8, 188u8, 252u8, 139u8, 241u8, 188u8, 3u8, 133u8];
        
        let ctx = test_scenario::ctx(&mut scenario);
        proximity::init_verifying_key(&server_cap, vk_bytes, ctx);
        
        test_scenario::return_to_sender(&scenario, server_cap);
    };

    // Create commitment with different coordinates
    scenario.next_tx(@0x1);
    {
        let server_cap = test_scenario::take_from_sender<proximity::ServerCap>(&scenario);
        let commitment_bytes = vector[16u8, 92u8, 223u8, 5u8, 218u8, 202u8, 177u8, 144u8, 179u8, 165u8, 237u8, 150u8, 235u8, 94u8, 55u8, 18u8, 76u8, 230u8, 153u8, 206u8, 129u8, 223u8, 203u8, 71u8, 140u8, 57u8, 24u8, 74u8, 146u8, 83u8, 3u8, 29u8]; // Different Poseidon commitment hash (32 bytes)
        let owner = @0x3;
        
        let ctx = test_scenario::ctx(&mut scenario);
        proximity::create_commitment(&server_cap, commitment_bytes, owner, ctx);
        
        test_scenario::return_to_sender(&scenario, server_cap);
    };

    // Verify proximity proof with different valid coordinates within 10km
    scenario.next_tx(@0x3);
    {
        let mut commitment = test_scenario::take_shared<proximity::LocationCommitment>(&scenario);
        let verifying_key = test_scenario::take_shared<proximity::VerifyingKey>(&scenario);
        let proof_bytes = vector[92u8, 14u8, 183u8, 35u8, 46u8, 165u8, 133u8, 152u8, 31u8, 127u8, 91u8, 113u8, 79u8, 37u8, 140u8, 199u8, 42u8, 173u8, 213u8, 77u8, 1u8, 109u8, 179u8, 223u8, 104u8, 253u8, 245u8, 218u8, 102u8, 165u8, 19u8, 29u8, 113u8, 105u8, 54u8, 209u8, 171u8, 82u8, 166u8, 106u8, 92u8, 228u8, 74u8, 60u8, 212u8, 205u8, 75u8, 123u8, 182u8, 96u8, 174u8, 229u8, 71u8, 3u8, 44u8, 161u8, 201u8, 69u8, 205u8, 133u8, 23u8, 191u8, 254u8, 26u8, 29u8, 192u8, 90u8, 8u8, 135u8, 77u8, 135u8, 31u8, 73u8, 35u8, 242u8, 11u8, 56u8, 155u8, 88u8, 231u8, 31u8, 119u8, 212u8, 98u8, 245u8, 100u8, 178u8, 57u8, 120u8, 13u8, 238u8, 245u8, 92u8, 131u8, 190u8, 166u8, 156u8, 182u8, 30u8, 109u8, 160u8, 99u8, 129u8, 165u8, 33u8, 193u8, 39u8, 161u8, 219u8, 10u8, 166u8, 213u8, 98u8, 68u8, 146u8, 159u8, 192u8, 242u8, 213u8, 157u8, 189u8, 172u8, 73u8, 79u8, 199u8, 17u8, 174u8, 143u8];
        let public_inputs = vector[16u8, 92u8, 223u8, 5u8, 218u8, 202u8, 177u8, 144u8, 179u8, 165u8, 237u8, 150u8, 235u8, 94u8, 55u8, 18u8, 76u8, 230u8, 153u8, 206u8, 129u8, 223u8, 203u8, 71u8, 140u8, 57u8, 24u8, 74u8, 146u8, 83u8, 3u8, 29u8, 0u8, 225u8, 245u8, 5u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8];
        
        let ctx = test_scenario::ctx(&mut scenario);
        proximity::verify_proximity_proof(&mut commitment, &verifying_key, proof_bytes, public_inputs, ctx);
        
        // Verify nonce was incremented
        let nonce = proximity::get_nonce(&commitment);
        assert!(nonce == 1, 0);
        
        test_scenario::return_shared(commitment);
        test_scenario::return_shared(verifying_key);
    };

    test_scenario::end(scenario);
}

#[test]
#[expected_failure]
fun test_invalid_inversed_sign_value_coordinates_fails() {
    use sui::test_scenario;

    let mut scenario = test_scenario::begin(@0x1);
    {
        let ctx = test_scenario::ctx(&mut scenario);
        proximity::init_for_testing(ctx);
    };

    // Initialize canonical verifying key
    scenario.next_tx(@0x1);
    {
        let server_cap = test_scenario::take_from_sender<proximity::ServerCap>(&scenario);
        let vk_bytes = vector[34u8, 114u8, 99u8, 209u8, 227u8, 104u8, 63u8, 7u8, 181u8, 6u8, 184u8, 240u8, 80u8, 69u8, 129u8, 104u8, 146u8, 26u8, 209u8, 150u8, 122u8, 180u8, 116u8, 242u8, 224u8, 10u8, 15u8, 209u8, 43u8, 213u8, 167u8, 0u8, 44u8, 194u8, 138u8, 172u8, 67u8, 149u8, 237u8, 45u8, 170u8, 184u8, 196u8, 3u8, 144u8, 166u8, 229u8, 108u8, 115u8, 214u8, 167u8, 45u8, 168u8, 65u8, 38u8, 83u8, 248u8, 24u8, 15u8, 247u8, 211u8, 73u8, 6u8, 1u8, 97u8, 152u8, 209u8, 206u8, 152u8, 174u8, 182u8, 23u8, 10u8, 0u8, 54u8, 124u8, 0u8, 197u8, 108u8, 155u8, 109u8, 196u8, 18u8, 214u8, 221u8, 145u8, 142u8, 126u8, 42u8, 93u8, 62u8, 200u8, 149u8, 247u8, 21u8, 151u8, 189u8, 161u8, 209u8, 113u8, 241u8, 151u8, 122u8, 9u8, 29u8, 80u8, 170u8, 44u8, 181u8, 50u8, 203u8, 207u8, 33u8, 64u8, 169u8, 44u8, 199u8, 242u8, 231u8, 59u8, 193u8, 150u8, 229u8, 216u8, 193u8, 236u8, 194u8, 12u8, 68u8, 168u8, 216u8, 54u8, 92u8, 81u8, 95u8, 254u8, 232u8, 75u8, 3u8, 235u8, 219u8, 141u8, 150u8, 169u8, 82u8, 141u8, 47u8, 59u8, 229u8, 97u8, 26u8, 194u8, 197u8, 85u8, 184u8, 192u8, 190u8, 160u8, 124u8, 162u8, 59u8, 242u8, 136u8, 193u8, 115u8, 3u8, 8u8, 91u8, 64u8, 42u8, 65u8, 187u8, 74u8, 40u8, 22u8, 20u8, 93u8, 30u8, 174u8, 235u8, 61u8, 19u8, 199u8, 3u8, 129u8, 137u8, 173u8, 151u8, 116u8, 234u8, 31u8, 15u8, 247u8, 212u8, 133u8, 77u8, 45u8, 82u8, 171u8, 255u8, 168u8, 119u8, 10u8, 10u8, 106u8, 39u8, 135u8, 110u8, 165u8, 171u8, 176u8, 234u8, 197u8, 5u8, 14u8, 94u8, 109u8, 180u8, 149u8, 186u8, 196u8, 7u8, 249u8, 172u8, 3u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 251u8, 27u8, 86u8, 50u8, 232u8, 158u8, 244u8, 235u8, 201u8, 32u8, 194u8, 147u8, 227u8, 62u8, 171u8, 64u8, 227u8, 21u8, 199u8, 103u8, 187u8, 73u8, 74u8, 221u8, 191u8, 80u8, 189u8, 98u8, 143u8, 218u8, 127u8, 22u8, 39u8, 94u8, 34u8, 59u8, 47u8, 70u8, 210u8, 233u8, 17u8, 18u8, 5u8, 200u8, 27u8, 165u8, 140u8, 26u8, 145u8, 67u8, 156u8, 161u8, 81u8, 4u8, 49u8, 166u8, 171u8, 222u8, 0u8, 128u8, 238u8, 40u8, 161u8, 8u8, 203u8, 99u8, 113u8, 178u8, 136u8, 9u8, 164u8, 221u8, 156u8, 185u8, 34u8, 37u8, 34u8, 140u8, 96u8, 149u8, 167u8, 216u8, 240u8, 214u8, 127u8, 246u8, 113u8, 69u8, 107u8, 188u8, 252u8, 139u8, 241u8, 188u8, 3u8, 133u8];
        
        let ctx = test_scenario::ctx(&mut scenario);
        proximity::init_verifying_key(&server_cap, vk_bytes, ctx);
        
        test_scenario::return_to_sender(&scenario, server_cap);
    };

    // Create commitment with absolute value coordinates
    scenario.next_tx(@0x1);
    {
        let server_cap = test_scenario::take_from_sender<proximity::ServerCap>(&scenario);
        let commitment_bytes = vector[106u8, 23u8, 111u8, 193u8, 168u8, 173u8, 3u8, 75u8, 212u8, 14u8, 223u8, 58u8, 141u8, 219u8, 198u8, 85u8, 102u8, 213u8, 166u8, 249u8, 150u8, 33u8, 15u8, 205u8, 131u8, 215u8, 128u8, 196u8, 116u8, 202u8, 249u8, 6u8]; // Absolute value Poseidon commitment hash (32 bytes)
        let owner = @0x4;
        
        let ctx = test_scenario::ctx(&mut scenario);
        proximity::create_commitment(&server_cap, commitment_bytes, owner, ctx);
        
        test_scenario::return_to_sender(&scenario, server_cap);
    };

    // Verify proximity proof with absolute value coordinates
    scenario.next_tx(@0x4);
    {
        let mut commitment = test_scenario::take_shared<proximity::LocationCommitment>(&scenario);
        let verifying_key = test_scenario::take_shared<proximity::VerifyingKey>(&scenario);
        let proof_bytes = vector[83u8, 139u8, 54u8, 189u8, 134u8, 135u8, 132u8, 123u8, 174u8, 119u8, 33u8, 62u8, 211u8, 222u8, 132u8, 164u8, 33u8, 146u8, 35u8, 105u8, 2u8, 65u8, 81u8, 242u8, 228u8, 161u8, 150u8, 232u8, 79u8, 65u8, 153u8, 33u8, 182u8, 138u8, 141u8, 27u8, 189u8, 229u8, 47u8, 153u8, 206u8, 17u8, 87u8, 101u8, 67u8, 16u8, 185u8, 38u8, 14u8, 158u8, 123u8, 26u8, 199u8, 238u8, 200u8, 132u8, 142u8, 232u8, 136u8, 190u8, 60u8, 34u8, 79u8, 32u8, 180u8, 147u8, 237u8, 35u8, 126u8, 66u8, 209u8, 134u8, 9u8, 0u8, 229u8, 37u8, 8u8, 40u8, 35u8, 29u8, 97u8, 123u8, 104u8, 52u8, 113u8, 255u8, 11u8, 156u8, 197u8, 58u8, 127u8, 29u8, 28u8, 189u8, 1u8, 21u8, 92u8, 44u8, 211u8, 109u8, 42u8, 239u8, 208u8, 132u8, 96u8, 35u8, 215u8, 147u8, 138u8, 121u8, 170u8, 23u8, 43u8, 246u8, 84u8, 207u8, 230u8, 251u8, 234u8, 37u8, 246u8, 99u8, 253u8, 19u8, 34u8, 176u8, 95u8, 168u8];
        let public_inputs = vector[145u8, 56u8, 219u8, 216u8, 111u8, 212u8, 2u8, 176u8, 162u8, 240u8, 40u8, 215u8, 255u8, 202u8, 30u8, 51u8, 141u8, 163u8, 230u8, 215u8, 225u8, 5u8, 26u8, 24u8, 171u8, 237u8, 7u8, 24u8, 34u8, 97u8, 255u8, 46u8, 0u8, 225u8, 245u8, 5u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8];
        
        let ctx = test_scenario::ctx(&mut scenario);
        proximity::verify_proximity_proof(&mut commitment, &verifying_key, proof_bytes, public_inputs, ctx);
        
        // Verify nonce was incremented
        let nonce = proximity::get_nonce(&commitment);
        assert!(nonce == 1, 0);
        
        test_scenario::return_shared(commitment);
        test_scenario::return_shared(verifying_key);
    };

    test_scenario::end(scenario);
}

// ============================================================================
// COMMITMENT BINDING TESTS
// Security tests to prevent proof reuse attacks across different commitments
// ============================================================================

#[test]
#[expected_failure(abort_code = 8, location = location_addr::proximity)]
fun test_commitment_hash_mismatch_fails() {
    use sui::test_scenario;

    let mut scenario = test_scenario::begin(@0x1);
    {
        let ctx = test_scenario::ctx(&mut scenario);
        proximity::init_for_testing(ctx);
    };

    // Initialize canonical verifying key
    scenario.next_tx(@0x1);
    {
        let server_cap = test_scenario::take_from_sender<proximity::ServerCap>(&scenario);
        let vk_bytes = vector[34u8, 114u8, 99u8, 209u8, 227u8, 104u8, 63u8, 7u8, 181u8, 6u8, 184u8, 240u8, 80u8, 69u8, 129u8, 104u8, 146u8, 26u8, 209u8, 150u8, 122u8, 180u8, 116u8, 242u8, 224u8, 10u8, 15u8, 209u8, 43u8, 213u8, 167u8, 0u8, 44u8, 194u8, 138u8, 172u8, 67u8, 149u8, 237u8, 45u8, 170u8, 184u8, 196u8, 3u8, 144u8, 166u8, 229u8, 108u8, 115u8, 214u8, 167u8, 45u8, 168u8, 65u8, 38u8, 83u8, 248u8, 24u8, 15u8, 247u8, 211u8, 73u8, 6u8, 1u8, 97u8, 152u8, 209u8, 206u8, 152u8, 174u8, 182u8, 23u8, 10u8, 0u8, 54u8, 124u8, 0u8, 197u8, 108u8, 155u8, 109u8, 196u8, 18u8, 214u8, 221u8, 145u8, 142u8, 126u8, 42u8, 93u8, 62u8, 200u8, 149u8, 247u8, 21u8, 151u8, 189u8, 161u8, 209u8, 113u8, 241u8, 151u8, 122u8, 9u8, 29u8, 80u8, 170u8, 44u8, 181u8, 50u8, 203u8, 207u8, 33u8, 64u8, 169u8, 44u8, 199u8, 242u8, 231u8, 59u8, 193u8, 150u8, 229u8, 216u8, 193u8, 236u8, 194u8, 12u8, 68u8, 168u8, 216u8, 54u8, 92u8, 81u8, 95u8, 254u8, 232u8, 75u8, 3u8, 235u8, 219u8, 141u8, 150u8, 169u8, 82u8, 141u8, 47u8, 59u8, 229u8, 97u8, 26u8, 194u8, 197u8, 85u8, 184u8, 192u8, 190u8, 160u8, 124u8, 162u8, 59u8, 242u8, 136u8, 193u8, 115u8, 3u8, 8u8, 91u8, 64u8, 42u8, 65u8, 187u8, 74u8, 40u8, 22u8, 20u8, 93u8, 30u8, 174u8, 235u8, 61u8, 19u8, 199u8, 3u8, 129u8, 137u8, 173u8, 151u8, 116u8, 234u8, 31u8, 15u8, 247u8, 212u8, 133u8, 77u8, 45u8, 82u8, 171u8, 255u8, 168u8, 119u8, 10u8, 10u8, 106u8, 39u8, 135u8, 110u8, 165u8, 171u8, 176u8, 234u8, 197u8, 5u8, 14u8, 94u8, 109u8, 180u8, 149u8, 186u8, 196u8, 7u8, 249u8, 172u8, 3u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 251u8, 27u8, 86u8, 50u8, 232u8, 158u8, 244u8, 235u8, 201u8, 32u8, 194u8, 147u8, 227u8, 62u8, 171u8, 64u8, 227u8, 21u8, 199u8, 103u8, 187u8, 73u8, 74u8, 221u8, 191u8, 80u8, 189u8, 98u8, 143u8, 218u8, 127u8, 22u8, 39u8, 94u8, 34u8, 59u8, 47u8, 70u8, 210u8, 233u8, 17u8, 18u8, 5u8, 200u8, 27u8, 165u8, 140u8, 26u8, 145u8, 67u8, 156u8, 161u8, 81u8, 4u8, 49u8, 166u8, 171u8, 222u8, 0u8, 128u8, 238u8, 40u8, 161u8, 8u8, 203u8, 99u8, 113u8, 178u8, 136u8, 9u8, 164u8, 221u8, 156u8, 185u8, 34u8, 37u8, 34u8, 140u8, 96u8, 149u8, 167u8, 216u8, 240u8, 214u8, 127u8, 246u8, 113u8, 69u8, 107u8, 188u8, 252u8, 139u8, 241u8, 188u8, 3u8, 133u8];
        
        let ctx = test_scenario::ctx(&mut scenario);
        proximity::init_verifying_key(&server_cap, vk_bytes, ctx);
        
        test_scenario::return_to_sender(&scenario, server_cap);
    };

    // Create commitment with SSU_B hash
    scenario.next_tx(@0x1);
    {
        let server_cap = test_scenario::take_from_sender<proximity::ServerCap>(&scenario);
        let commitment_b_bytes = vector[16u8, 92u8, 223u8, 5u8, 218u8, 202u8, 177u8, 144u8, 179u8, 165u8, 237u8, 150u8, 235u8, 94u8, 55u8, 18u8, 76u8, 230u8, 153u8, 206u8, 129u8, 223u8, 203u8, 71u8, 140u8, 57u8, 24u8, 74u8, 146u8, 83u8, 3u8, 29u8]; // SSU_B commitment hash
        let owner = @0x2;
        
        let ctx = test_scenario::ctx(&mut scenario);
        proximity::create_commitment(&server_cap, commitment_b_bytes, owner, ctx);
        
        test_scenario::return_to_sender(&scenario, server_cap);
    };

    // SECURITY TEST: Attempt to use proof with WRONG commitment hash in public inputs
    // This simulates an attacker trying to "reuse" a valid proof with a different commitment
    scenario.next_tx(@0x2);
    {
        let mut commitment = test_scenario::take_shared<proximity::LocationCommitment>(&scenario);
        let verifying_key = test_scenario::take_shared<proximity::VerifyingKey>(&scenario);
        
        let ctx = test_scenario::ctx(&mut scenario);
        
        // ATTACK SCENARIO:
        // - The stored commitment has SSU_B's hash
        // - We provide public inputs with SSU_A's hash
        // - The proof is cryptographically valid but for the WRONG commitment
        //
        // EXPECTED RESULT: FAIL with error code 8
        // The verify_commitment_binding() function will compare:
        //   public_inputs[0..32] (SSU_A hash) != commitment.commitment (SSU_B hash)
        // And abort with error code 8: "commitment hash mismatch - proof not for this location"
        
        let proof_for_ssu_a = vector[83u8, 139u8, 54u8, 189u8, 134u8, 135u8, 132u8, 123u8, 174u8, 119u8, 33u8, 62u8, 211u8, 222u8, 132u8, 164u8, 33u8, 146u8, 35u8, 105u8, 2u8, 65u8, 81u8, 242u8, 228u8, 161u8, 150u8, 232u8, 79u8, 65u8, 153u8, 33u8, 182u8, 138u8, 141u8, 27u8, 189u8, 229u8, 47u8, 153u8, 206u8, 17u8, 87u8, 101u8, 67u8, 16u8, 185u8, 38u8, 14u8, 158u8, 123u8, 26u8, 199u8, 238u8, 200u8, 132u8, 142u8, 232u8, 136u8, 190u8, 60u8, 34u8, 79u8, 32u8, 180u8, 147u8, 237u8, 35u8, 126u8, 66u8, 209u8, 134u8, 9u8, 0u8, 229u8, 37u8, 8u8, 40u8, 35u8, 29u8, 97u8, 123u8, 104u8, 52u8, 113u8, 255u8, 11u8, 156u8, 197u8, 58u8, 127u8, 29u8, 28u8, 189u8, 1u8, 21u8, 92u8, 44u8, 211u8, 109u8, 42u8, 239u8, 208u8, 132u8, 96u8, 35u8, 215u8, 147u8, 138u8, 121u8, 170u8, 23u8, 43u8, 246u8, 84u8, 207u8, 230u8, 251u8, 234u8, 37u8, 246u8, 99u8, 253u8, 19u8, 34u8, 176u8, 95u8, 168u8]; // Valid proof for SSU_A
        let public_inputs_for_ssu_a = vector[145u8, 56u8, 219u8, 216u8, 111u8, 212u8, 2u8, 176u8, 162u8, 240u8, 40u8, 215u8, 255u8, 202u8, 30u8, 51u8, 141u8, 163u8, 230u8, 215u8, 225u8, 5u8, 26u8, 24u8, 171u8, 237u8, 7u8, 24u8, 34u8, 97u8, 255u8, 46u8, 0u8, 225u8, 245u8, 5u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8]; // Public inputs containing SSU_A's hash (WRONG!)
        
        proximity::verify_proximity_proof(
            &mut commitment,  // Commitment object with SSU_B's hash
            &verifying_key, 
            proof_for_ssu_a,  // Proof (doesn't matter - fails before cryptographic check)
            public_inputs_for_ssu_a,  // Public inputs containing SSU_A's hash (WRONG!)
            ctx
        );
        
        // This line should never be reached
        test_scenario::return_shared(commitment);
        test_scenario::return_shared(verifying_key);
    };

    test_scenario::end(scenario);
}

#[test]
fun test_proof_works_with_correct_commitment() {
    use sui::test_scenario;

    let mut scenario = test_scenario::begin(@0x1);
    {
        let ctx = test_scenario::ctx(&mut scenario);
        proximity::init_for_testing(ctx);
    };

    // Initialize canonical verifying key
    scenario.next_tx(@0x1);
    {
        let server_cap = test_scenario::take_from_sender<proximity::ServerCap>(&scenario);
        let vk_bytes = vector[34u8, 114u8, 99u8, 209u8, 227u8, 104u8, 63u8, 7u8, 181u8, 6u8, 184u8, 240u8, 80u8, 69u8, 129u8, 104u8, 146u8, 26u8, 209u8, 150u8, 122u8, 180u8, 116u8, 242u8, 224u8, 10u8, 15u8, 209u8, 43u8, 213u8, 167u8, 0u8, 44u8, 194u8, 138u8, 172u8, 67u8, 149u8, 237u8, 45u8, 170u8, 184u8, 196u8, 3u8, 144u8, 166u8, 229u8, 108u8, 115u8, 214u8, 167u8, 45u8, 168u8, 65u8, 38u8, 83u8, 248u8, 24u8, 15u8, 247u8, 211u8, 73u8, 6u8, 1u8, 97u8, 152u8, 209u8, 206u8, 152u8, 174u8, 182u8, 23u8, 10u8, 0u8, 54u8, 124u8, 0u8, 197u8, 108u8, 155u8, 109u8, 196u8, 18u8, 214u8, 221u8, 145u8, 142u8, 126u8, 42u8, 93u8, 62u8, 200u8, 149u8, 247u8, 21u8, 151u8, 189u8, 161u8, 209u8, 113u8, 241u8, 151u8, 122u8, 9u8, 29u8, 80u8, 170u8, 44u8, 181u8, 50u8, 203u8, 207u8, 33u8, 64u8, 169u8, 44u8, 199u8, 242u8, 231u8, 59u8, 193u8, 150u8, 229u8, 216u8, 193u8, 236u8, 194u8, 12u8, 68u8, 168u8, 216u8, 54u8, 92u8, 81u8, 95u8, 254u8, 232u8, 75u8, 3u8, 235u8, 219u8, 141u8, 150u8, 169u8, 82u8, 141u8, 47u8, 59u8, 229u8, 97u8, 26u8, 194u8, 197u8, 85u8, 184u8, 192u8, 190u8, 160u8, 124u8, 162u8, 59u8, 242u8, 136u8, 193u8, 115u8, 3u8, 8u8, 91u8, 64u8, 42u8, 65u8, 187u8, 74u8, 40u8, 22u8, 20u8, 93u8, 30u8, 174u8, 235u8, 61u8, 19u8, 199u8, 3u8, 129u8, 137u8, 173u8, 151u8, 116u8, 234u8, 31u8, 15u8, 247u8, 212u8, 133u8, 77u8, 45u8, 82u8, 171u8, 255u8, 168u8, 119u8, 10u8, 10u8, 106u8, 39u8, 135u8, 110u8, 165u8, 171u8, 176u8, 234u8, 197u8, 5u8, 14u8, 94u8, 109u8, 180u8, 149u8, 186u8, 196u8, 7u8, 249u8, 172u8, 3u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 251u8, 27u8, 86u8, 50u8, 232u8, 158u8, 244u8, 235u8, 201u8, 32u8, 194u8, 147u8, 227u8, 62u8, 171u8, 64u8, 227u8, 21u8, 199u8, 103u8, 187u8, 73u8, 74u8, 221u8, 191u8, 80u8, 189u8, 98u8, 143u8, 218u8, 127u8, 22u8, 39u8, 94u8, 34u8, 59u8, 47u8, 70u8, 210u8, 233u8, 17u8, 18u8, 5u8, 200u8, 27u8, 165u8, 140u8, 26u8, 145u8, 67u8, 156u8, 161u8, 81u8, 4u8, 49u8, 166u8, 171u8, 222u8, 0u8, 128u8, 238u8, 40u8, 161u8, 8u8, 203u8, 99u8, 113u8, 178u8, 136u8, 9u8, 164u8, 221u8, 156u8, 185u8, 34u8, 37u8, 34u8, 140u8, 96u8, 149u8, 167u8, 216u8, 240u8, 214u8, 127u8, 246u8, 113u8, 69u8, 107u8, 188u8, 252u8, 139u8, 241u8, 188u8, 3u8, 133u8];
        
        let ctx = test_scenario::ctx(&mut scenario);
        proximity::init_verifying_key(&server_cap, vk_bytes, ctx);
        
        test_scenario::return_to_sender(&scenario, server_cap);
    };

    // Create commitment with SSU_A hash
    scenario.next_tx(@0x1);
    {
        let server_cap = test_scenario::take_from_sender<proximity::ServerCap>(&scenario);
        let commitment_bytes = vector[145u8, 56u8, 219u8, 216u8, 111u8, 212u8, 2u8, 176u8, 162u8, 240u8, 40u8, 215u8, 255u8, 202u8, 30u8, 51u8, 141u8, 163u8, 230u8, 215u8, 225u8, 5u8, 26u8, 24u8, 171u8, 237u8, 7u8, 24u8, 34u8, 97u8, 255u8, 46u8]; // SSU_A commitment hash
        let owner = @0x2;
        
        let ctx = test_scenario::ctx(&mut scenario);
        proximity::create_commitment(&server_cap, commitment_bytes, owner, ctx);
        
        test_scenario::return_to_sender(&scenario, server_cap);
    };

    // Verify proof with CORRECT matching commitment - should succeed
    scenario.next_tx(@0x2);
    {
        let mut commitment = test_scenario::take_shared<proximity::LocationCommitment>(&scenario);
        let verifying_key = test_scenario::take_shared<proximity::VerifyingKey>(&scenario);
        let proof_bytes = vector[83u8, 139u8, 54u8, 189u8, 134u8, 135u8, 132u8, 123u8, 174u8, 119u8, 33u8, 62u8, 211u8, 222u8, 132u8, 164u8, 33u8, 146u8, 35u8, 105u8, 2u8, 65u8, 81u8, 242u8, 228u8, 161u8, 150u8, 232u8, 79u8, 65u8, 153u8, 33u8, 182u8, 138u8, 141u8, 27u8, 189u8, 229u8, 47u8, 153u8, 206u8, 17u8, 87u8, 101u8, 67u8, 16u8, 185u8, 38u8, 14u8, 158u8, 123u8, 26u8, 199u8, 238u8, 200u8, 132u8, 142u8, 232u8, 136u8, 190u8, 60u8, 34u8, 79u8, 32u8, 180u8, 147u8, 237u8, 35u8, 126u8, 66u8, 209u8, 134u8, 9u8, 0u8, 229u8, 37u8, 8u8, 40u8, 35u8, 29u8, 97u8, 123u8, 104u8, 52u8, 113u8, 255u8, 11u8, 156u8, 197u8, 58u8, 127u8, 29u8, 28u8, 189u8, 1u8, 21u8, 92u8, 44u8, 211u8, 109u8, 42u8, 239u8, 208u8, 132u8, 96u8, 35u8, 215u8, 147u8, 138u8, 121u8, 170u8, 23u8, 43u8, 246u8, 84u8, 207u8, 230u8, 251u8, 234u8, 37u8, 246u8, 99u8, 253u8, 19u8, 34u8, 176u8, 95u8, 168u8]; // Valid proof for SSU_A
        let public_inputs = vector[145u8, 56u8, 219u8, 216u8, 111u8, 212u8, 2u8, 176u8, 162u8, 240u8, 40u8, 215u8, 255u8, 202u8, 30u8, 51u8, 141u8, 163u8, 230u8, 215u8, 225u8, 5u8, 26u8, 24u8, 171u8, 237u8, 7u8, 24u8, 34u8, 97u8, 255u8, 46u8, 0u8, 225u8, 245u8, 5u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8]; // Public inputs with SSU_A hash (CORRECT!)
        
        let ctx = test_scenario::ctx(&mut scenario);
        
        // This should SUCCEED because commitment hash in public inputs matches commitment object
        proximity::verify_proximity_proof(&mut commitment, &verifying_key, proof_bytes, public_inputs, ctx);
        
        // Verify nonce was incremented (proof succeeded)
        let nonce = proximity::get_nonce(&commitment);
        assert!(nonce == 1, 0);
        
        test_scenario::return_shared(commitment);
        test_scenario::return_shared(verifying_key);
    };

    test_scenario::end(scenario);
}
