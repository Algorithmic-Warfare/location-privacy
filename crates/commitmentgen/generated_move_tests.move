
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
        let vk_bytes = vector[229u8, 122u8, 162u8, 112u8, 40u8, 77u8, 47u8, 228u8, 92u8, 145u8, 25u8, 175u8, 109u8, 140u8, 97u8, 125u8, 216u8, 110u8, 240u8, 107u8, 29u8, 83u8, 241u8, 39u8, 191u8, 150u8, 18u8, 254u8, 76u8, 120u8, 163u8, 142u8, 136u8, 229u8, 4u8, 112u8, 29u8, 104u8, 157u8, 254u8, 17u8, 102u8, 250u8, 144u8, 132u8, 87u8, 69u8, 126u8, 255u8, 179u8, 64u8, 67u8, 127u8, 236u8, 61u8, 225u8, 54u8, 234u8, 26u8, 10u8, 58u8, 154u8, 92u8, 10u8, 250u8, 241u8, 0u8, 221u8, 56u8, 82u8, 235u8, 21u8, 8u8, 35u8, 138u8, 176u8, 88u8, 192u8, 141u8, 255u8, 17u8, 153u8, 45u8, 189u8, 195u8, 228u8, 176u8, 228u8, 120u8, 146u8, 59u8, 82u8, 207u8, 59u8, 188u8, 43u8, 147u8, 88u8, 162u8, 103u8, 147u8, 14u8, 133u8, 167u8, 53u8, 65u8, 55u8, 49u8, 45u8, 171u8, 5u8, 5u8, 123u8, 154u8, 240u8, 52u8, 208u8, 216u8, 151u8, 254u8, 68u8, 133u8, 19u8, 21u8, 126u8, 41u8, 197u8, 43u8, 98u8, 164u8, 11u8, 82u8, 82u8, 244u8, 195u8, 1u8, 186u8, 40u8, 71u8, 142u8, 179u8, 233u8, 70u8, 119u8, 120u8, 140u8, 59u8, 162u8, 25u8, 56u8, 176u8, 3u8, 209u8, 130u8, 85u8, 28u8, 118u8, 96u8, 5u8, 141u8, 183u8, 65u8, 216u8, 47u8, 112u8, 8u8, 105u8, 136u8, 140u8, 44u8, 101u8, 202u8, 151u8, 12u8, 76u8, 26u8, 42u8, 142u8, 178u8, 55u8, 112u8, 254u8, 57u8, 192u8, 39u8, 11u8, 31u8, 149u8, 81u8, 164u8, 56u8, 35u8, 62u8, 9u8, 153u8, 202u8, 73u8, 151u8, 33u8, 81u8, 119u8, 100u8, 29u8, 105u8, 65u8, 91u8, 191u8, 9u8, 15u8, 50u8, 86u8, 226u8, 223u8, 172u8, 127u8, 181u8, 242u8, 49u8, 178u8, 109u8, 106u8, 34u8, 37u8, 31u8, 3u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 86u8, 171u8, 102u8, 229u8, 201u8, 61u8, 216u8, 222u8, 166u8, 194u8, 138u8, 122u8, 129u8, 122u8, 157u8, 29u8, 60u8, 162u8, 33u8, 105u8, 104u8, 199u8, 119u8, 150u8, 99u8, 138u8, 140u8, 66u8, 51u8, 244u8, 142u8, 34u8, 241u8, 86u8, 175u8, 167u8, 70u8, 142u8, 41u8, 222u8, 42u8, 19u8, 203u8, 145u8, 146u8, 220u8, 243u8, 75u8, 219u8, 44u8, 140u8, 170u8, 58u8, 183u8, 95u8, 130u8, 13u8, 186u8, 31u8, 0u8, 109u8, 26u8, 180u8, 14u8, 9u8, 151u8, 253u8, 48u8, 138u8, 235u8, 173u8, 74u8, 69u8, 59u8, 217u8, 230u8, 138u8, 209u8, 28u8, 197u8, 216u8, 126u8, 127u8, 254u8, 216u8, 164u8, 201u8, 24u8, 104u8, 31u8, 60u8, 42u8, 105u8, 100u8, 200u8, 16u8]; // Canonical verifying key (328 bytes)
        
        let ctx = test_scenario::ctx(&mut scenario);
        proximity::init_verifying_key(&server_cap, vk_bytes, ctx);
        
        test_scenario::return_to_sender(&scenario, server_cap);
    };

    // Create commitment (Poseidon hash - 32 bytes)
    scenario.next_tx(@0x1);
    {
        let server_cap = test_scenario::take_from_sender<proximity::ServerCap>(&scenario);
        let commitment_bytes = vector[30u8, 30u8, 219u8, 114u8, 159u8, 179u8, 170u8, 234u8, 98u8, 71u8, 60u8, 126u8, 131u8, 44u8, 69u8, 89u8, 147u8, 254u8, 101u8, 171u8, 191u8, 13u8, 178u8, 13u8, 210u8, 140u8, 12u8, 48u8, 206u8, 119u8, 224u8, 43u8]; // Poseidon hash (32 bytes)
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
        let proof_bytes = vector[12u8, 171u8, 22u8, 202u8, 201u8, 57u8, 198u8, 101u8, 117u8, 217u8, 32u8, 40u8, 146u8, 37u8, 241u8, 144u8, 89u8, 91u8, 77u8, 3u8, 155u8, 120u8, 64u8, 57u8, 71u8, 76u8, 146u8, 249u8, 8u8, 129u8, 136u8, 148u8, 141u8, 73u8, 144u8, 28u8, 5u8, 8u8, 251u8, 119u8, 78u8, 72u8, 96u8, 197u8, 233u8, 11u8, 93u8, 225u8, 69u8, 125u8, 47u8, 90u8, 148u8, 197u8, 237u8, 122u8, 29u8, 224u8, 241u8, 116u8, 239u8, 145u8, 179u8, 28u8, 83u8, 71u8, 51u8, 147u8, 197u8, 25u8, 62u8, 231u8, 127u8, 64u8, 22u8, 242u8, 121u8, 129u8, 30u8, 139u8, 25u8, 109u8, 46u8, 161u8, 171u8, 223u8, 219u8, 108u8, 210u8, 33u8, 124u8, 164u8, 66u8, 132u8, 176u8, 20u8, 197u8, 176u8, 19u8, 185u8, 123u8, 51u8, 35u8, 60u8, 17u8, 234u8, 142u8, 121u8, 171u8, 7u8, 149u8, 229u8, 204u8, 42u8, 204u8, 121u8, 217u8, 155u8, 125u8, 83u8, 180u8, 12u8, 241u8, 66u8, 255u8, 204u8, 206u8, 158u8];
        let public_inputs = vector[30u8, 30u8, 219u8, 114u8, 159u8, 179u8, 170u8, 234u8, 98u8, 71u8, 60u8, 126u8, 131u8, 44u8, 69u8, 89u8, 147u8, 254u8, 101u8, 171u8, 191u8, 13u8, 178u8, 13u8, 210u8, 140u8, 12u8, 48u8, 206u8, 119u8, 224u8, 43u8, 0u8, 225u8, 245u8, 5u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8]; // [commitment_hash, max_distance_squared] (64 bytes total)
        
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
        let vk_bytes = vector[229u8, 122u8, 162u8, 112u8, 40u8, 77u8, 47u8, 228u8, 92u8, 145u8, 25u8, 175u8, 109u8, 140u8, 97u8, 125u8, 216u8, 110u8, 240u8, 107u8, 29u8, 83u8, 241u8, 39u8, 191u8, 150u8, 18u8, 254u8, 76u8, 120u8, 163u8, 142u8, 136u8, 229u8, 4u8, 112u8, 29u8, 104u8, 157u8, 254u8, 17u8, 102u8, 250u8, 144u8, 132u8, 87u8, 69u8, 126u8, 255u8, 179u8, 64u8, 67u8, 127u8, 236u8, 61u8, 225u8, 54u8, 234u8, 26u8, 10u8, 58u8, 154u8, 92u8, 10u8, 250u8, 241u8, 0u8, 221u8, 56u8, 82u8, 235u8, 21u8, 8u8, 35u8, 138u8, 176u8, 88u8, 192u8, 141u8, 255u8, 17u8, 153u8, 45u8, 189u8, 195u8, 228u8, 176u8, 228u8, 120u8, 146u8, 59u8, 82u8, 207u8, 59u8, 188u8, 43u8, 147u8, 88u8, 162u8, 103u8, 147u8, 14u8, 133u8, 167u8, 53u8, 65u8, 55u8, 49u8, 45u8, 171u8, 5u8, 5u8, 123u8, 154u8, 240u8, 52u8, 208u8, 216u8, 151u8, 254u8, 68u8, 133u8, 19u8, 21u8, 126u8, 41u8, 197u8, 43u8, 98u8, 164u8, 11u8, 82u8, 82u8, 244u8, 195u8, 1u8, 186u8, 40u8, 71u8, 142u8, 179u8, 233u8, 70u8, 119u8, 120u8, 140u8, 59u8, 162u8, 25u8, 56u8, 176u8, 3u8, 209u8, 130u8, 85u8, 28u8, 118u8, 96u8, 5u8, 141u8, 183u8, 65u8, 216u8, 47u8, 112u8, 8u8, 105u8, 136u8, 140u8, 44u8, 101u8, 202u8, 151u8, 12u8, 76u8, 26u8, 42u8, 142u8, 178u8, 55u8, 112u8, 254u8, 57u8, 192u8, 39u8, 11u8, 31u8, 149u8, 81u8, 164u8, 56u8, 35u8, 62u8, 9u8, 153u8, 202u8, 73u8, 151u8, 33u8, 81u8, 119u8, 100u8, 29u8, 105u8, 65u8, 91u8, 191u8, 9u8, 15u8, 50u8, 86u8, 226u8, 223u8, 172u8, 127u8, 181u8, 242u8, 49u8, 178u8, 109u8, 106u8, 34u8, 37u8, 31u8, 3u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 86u8, 171u8, 102u8, 229u8, 201u8, 61u8, 216u8, 222u8, 166u8, 194u8, 138u8, 122u8, 129u8, 122u8, 157u8, 29u8, 60u8, 162u8, 33u8, 105u8, 104u8, 199u8, 119u8, 150u8, 99u8, 138u8, 140u8, 66u8, 51u8, 244u8, 142u8, 34u8, 241u8, 86u8, 175u8, 167u8, 70u8, 142u8, 41u8, 222u8, 42u8, 19u8, 203u8, 145u8, 146u8, 220u8, 243u8, 75u8, 219u8, 44u8, 140u8, 170u8, 58u8, 183u8, 95u8, 130u8, 13u8, 186u8, 31u8, 0u8, 109u8, 26u8, 180u8, 14u8, 9u8, 151u8, 253u8, 48u8, 138u8, 235u8, 173u8, 74u8, 69u8, 59u8, 217u8, 230u8, 138u8, 209u8, 28u8, 197u8, 216u8, 126u8, 127u8, 254u8, 216u8, 164u8, 201u8, 24u8, 104u8, 31u8, 60u8, 42u8, 105u8, 100u8, 200u8, 16u8];
        
        let ctx = test_scenario::ctx(&mut scenario);
        proximity::init_verifying_key(&server_cap, vk_bytes, ctx);
        
        test_scenario::return_to_sender(&scenario, server_cap);
    };

    // Create commitment
    scenario.next_tx(@0x1);
    {
        let server_cap = test_scenario::take_from_sender<proximity::ServerCap>(&scenario);
        let commitment_bytes = vector[30u8, 30u8, 219u8, 114u8, 159u8, 179u8, 170u8, 234u8, 98u8, 71u8, 60u8, 126u8, 131u8, 44u8, 69u8, 89u8, 147u8, 254u8, 101u8, 171u8, 191u8, 13u8, 178u8, 13u8, 210u8, 140u8, 12u8, 48u8, 206u8, 119u8, 224u8, 43u8];
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
        let proof_bytes = vector[12u8, 171u8, 22u8, 202u8, 201u8, 57u8, 198u8, 101u8, 117u8, 217u8, 223u8, 40u8, 146u8, 37u8, 241u8, 144u8, 89u8, 91u8, 77u8, 3u8, 155u8, 120u8, 64u8, 57u8, 71u8, 76u8, 146u8, 249u8, 8u8, 129u8, 136u8, 148u8, 141u8, 73u8, 144u8, 28u8, 5u8, 8u8, 251u8, 119u8, 78u8, 72u8, 96u8, 197u8, 233u8, 11u8, 93u8, 225u8, 69u8, 125u8, 47u8, 90u8, 148u8, 197u8, 237u8, 122u8, 29u8, 224u8, 241u8, 116u8, 239u8, 145u8, 179u8, 28u8, 83u8, 71u8, 51u8, 147u8, 197u8, 25u8, 62u8, 231u8, 127u8, 64u8, 22u8, 242u8, 121u8, 129u8, 30u8, 139u8, 25u8, 109u8, 46u8, 161u8, 171u8, 223u8, 219u8, 108u8, 210u8, 33u8, 124u8, 164u8, 66u8, 132u8, 176u8, 20u8, 197u8, 176u8, 19u8, 185u8, 123u8, 51u8, 35u8, 60u8, 17u8, 234u8, 142u8, 121u8, 171u8, 7u8, 149u8, 229u8, 204u8, 42u8, 204u8, 121u8, 217u8, 155u8, 125u8, 83u8, 180u8, 12u8, 241u8, 66u8, 255u8, 204u8, 206u8, 158u8]; // Corrupted proof bytes
        let public_inputs = vector[30u8, 30u8, 219u8, 114u8, 159u8, 179u8, 170u8, 234u8, 98u8, 71u8, 60u8, 126u8, 131u8, 44u8, 69u8, 89u8, 147u8, 254u8, 101u8, 171u8, 191u8, 13u8, 178u8, 13u8, 210u8, 140u8, 12u8, 48u8, 206u8, 119u8, 224u8, 43u8, 0u8, 225u8, 245u8, 5u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8];
        
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
        let wrong_vk_bytes = vector[106u8, 128u8, 252u8, 124u8, 83u8, 51u8, 78u8, 241u8, 23u8, 59u8, 184u8, 36u8, 16u8, 103u8, 22u8, 243u8, 222u8, 41u8, 92u8, 134u8, 126u8, 92u8, 149u8, 245u8, 64u8, 197u8, 82u8, 55u8, 58u8, 108u8, 204u8, 2u8, 172u8, 227u8, 92u8, 173u8, 255u8, 67u8, 63u8, 176u8, 0u8, 126u8, 183u8, 115u8, 53u8, 69u8, 6u8, 55u8, 21u8, 181u8, 31u8, 1u8, 1u8, 158u8, 252u8, 107u8, 36u8, 212u8, 221u8, 68u8, 199u8, 95u8, 60u8, 6u8, 35u8, 43u8, 153u8, 198u8, 14u8, 103u8, 133u8, 142u8, 87u8, 180u8, 64u8, 201u8, 138u8, 24u8, 144u8, 108u8, 57u8, 239u8, 180u8, 62u8, 164u8, 237u8, 58u8, 36u8, 99u8, 10u8, 249u8, 172u8, 144u8, 228u8, 50u8, 149u8, 9u8, 202u8, 200u8, 19u8, 201u8, 119u8, 211u8, 240u8, 238u8, 218u8, 167u8, 227u8, 21u8, 241u8, 180u8, 106u8, 19u8, 196u8, 203u8, 206u8, 254u8, 164u8, 140u8, 86u8, 229u8, 41u8, 3u8, 11u8, 9u8, 176u8, 225u8, 1u8, 129u8, 7u8, 65u8, 159u8, 48u8, 53u8, 130u8, 2u8, 44u8, 107u8, 245u8, 171u8, 125u8, 50u8, 35u8, 63u8, 76u8, 200u8, 124u8, 120u8, 249u8, 253u8, 233u8, 211u8, 40u8, 159u8, 108u8, 128u8, 179u8, 52u8, 102u8, 133u8, 32u8, 165u8, 202u8, 153u8, 101u8, 215u8, 41u8, 209u8, 124u8, 178u8, 67u8, 153u8, 128u8, 154u8, 140u8, 154u8, 52u8, 231u8, 127u8, 102u8, 147u8, 38u8, 68u8, 48u8, 221u8, 32u8, 159u8, 126u8, 117u8, 115u8, 94u8, 40u8, 21u8, 21u8, 107u8, 1u8, 72u8, 64u8, 139u8, 147u8, 208u8, 114u8, 179u8, 15u8, 144u8, 5u8, 14u8, 93u8, 81u8, 250u8, 189u8, 107u8, 217u8, 42u8, 101u8, 137u8, 74u8, 235u8, 68u8, 173u8, 25u8, 33u8, 97u8, 165u8, 3u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 196u8, 198u8, 152u8, 225u8, 208u8, 21u8, 28u8, 85u8, 199u8, 104u8, 209u8, 112u8, 98u8, 126u8, 80u8, 19u8, 232u8, 218u8, 89u8, 141u8, 154u8, 163u8, 34u8, 145u8, 86u8, 139u8, 246u8, 205u8, 239u8, 241u8, 85u8, 42u8, 217u8, 178u8, 84u8, 46u8, 215u8, 87u8, 211u8, 131u8, 193u8, 160u8, 135u8, 215u8, 163u8, 66u8, 18u8, 145u8, 9u8, 145u8, 121u8, 7u8, 147u8, 166u8, 235u8, 215u8, 137u8, 188u8, 106u8, 206u8, 68u8, 118u8, 223u8, 20u8, 53u8, 140u8, 35u8, 212u8, 28u8, 241u8, 255u8, 199u8, 211u8, 165u8, 135u8, 144u8, 121u8, 164u8, 53u8, 171u8, 78u8, 65u8, 75u8, 54u8, 94u8, 120u8, 111u8, 9u8, 87u8, 159u8, 128u8, 22u8, 74u8, 3u8, 57u8, 19u8]; // Wrong VK bytes (from different trusted setup)
        
        let ctx = test_scenario::ctx(&mut scenario);
        proximity::init_verifying_key(&server_cap, wrong_vk_bytes, ctx);
        
        test_scenario::return_to_sender(&scenario, server_cap);
    };

    // Create commitment
    scenario.next_tx(@0x1);
    {
        let server_cap = test_scenario::take_from_sender<proximity::ServerCap>(&scenario);
        let commitment_bytes = vector[30u8, 30u8, 219u8, 114u8, 159u8, 179u8, 170u8, 234u8, 98u8, 71u8, 60u8, 126u8, 131u8, 44u8, 69u8, 89u8, 147u8, 254u8, 101u8, 171u8, 191u8, 13u8, 178u8, 13u8, 210u8, 140u8, 12u8, 48u8, 206u8, 119u8, 224u8, 43u8];
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
        let proof_bytes = vector[12u8, 171u8, 22u8, 202u8, 201u8, 57u8, 198u8, 101u8, 117u8, 217u8, 32u8, 40u8, 146u8, 37u8, 241u8, 144u8, 89u8, 91u8, 77u8, 3u8, 155u8, 120u8, 64u8, 57u8, 71u8, 76u8, 146u8, 249u8, 8u8, 129u8, 136u8, 148u8, 141u8, 73u8, 144u8, 28u8, 5u8, 8u8, 251u8, 119u8, 78u8, 72u8, 96u8, 197u8, 233u8, 11u8, 93u8, 225u8, 69u8, 125u8, 47u8, 90u8, 148u8, 197u8, 237u8, 122u8, 29u8, 224u8, 241u8, 116u8, 239u8, 145u8, 179u8, 28u8, 83u8, 71u8, 51u8, 147u8, 197u8, 25u8, 62u8, 231u8, 127u8, 64u8, 22u8, 242u8, 121u8, 129u8, 30u8, 139u8, 25u8, 109u8, 46u8, 161u8, 171u8, 223u8, 219u8, 108u8, 210u8, 33u8, 124u8, 164u8, 66u8, 132u8, 176u8, 20u8, 197u8, 176u8, 19u8, 185u8, 123u8, 51u8, 35u8, 60u8, 17u8, 234u8, 142u8, 121u8, 171u8, 7u8, 149u8, 229u8, 204u8, 42u8, 204u8, 121u8, 217u8, 155u8, 125u8, 83u8, 180u8, 12u8, 241u8, 66u8, 255u8, 204u8, 206u8, 158u8]; // Proof generated with correct VK
        let public_inputs = vector[30u8, 30u8, 219u8, 114u8, 159u8, 179u8, 170u8, 234u8, 98u8, 71u8, 60u8, 126u8, 131u8, 44u8, 69u8, 89u8, 147u8, 254u8, 101u8, 171u8, 191u8, 13u8, 178u8, 13u8, 210u8, 140u8, 12u8, 48u8, 206u8, 119u8, 224u8, 43u8, 0u8, 225u8, 245u8, 5u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8];
        
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
        let vk_bytes = vector[229u8, 122u8, 162u8, 112u8, 40u8, 77u8, 47u8, 228u8, 92u8, 145u8, 25u8, 175u8, 109u8, 140u8, 97u8, 125u8, 216u8, 110u8, 240u8, 107u8, 29u8, 83u8, 241u8, 39u8, 191u8, 150u8, 18u8, 254u8, 76u8, 120u8, 163u8, 142u8, 136u8, 229u8, 4u8, 112u8, 29u8, 104u8, 157u8, 254u8, 17u8, 102u8, 250u8, 144u8, 132u8, 87u8, 69u8, 126u8, 255u8, 179u8, 64u8, 67u8, 127u8, 236u8, 61u8, 225u8, 54u8, 234u8, 26u8, 10u8, 58u8, 154u8, 92u8, 10u8, 250u8, 241u8, 0u8, 221u8, 56u8, 82u8, 235u8, 21u8, 8u8, 35u8, 138u8, 176u8, 88u8, 192u8, 141u8, 255u8, 17u8, 153u8, 45u8, 189u8, 195u8, 228u8, 176u8, 228u8, 120u8, 146u8, 59u8, 82u8, 207u8, 59u8, 188u8, 43u8, 147u8, 88u8, 162u8, 103u8, 147u8, 14u8, 133u8, 167u8, 53u8, 65u8, 55u8, 49u8, 45u8, 171u8, 5u8, 5u8, 123u8, 154u8, 240u8, 52u8, 208u8, 216u8, 151u8, 254u8, 68u8, 133u8, 19u8, 21u8, 126u8, 41u8, 197u8, 43u8, 98u8, 164u8, 11u8, 82u8, 82u8, 244u8, 195u8, 1u8, 186u8, 40u8, 71u8, 142u8, 179u8, 233u8, 70u8, 119u8, 120u8, 140u8, 59u8, 162u8, 25u8, 56u8, 176u8, 3u8, 209u8, 130u8, 85u8, 28u8, 118u8, 96u8, 5u8, 141u8, 183u8, 65u8, 216u8, 47u8, 112u8, 8u8, 105u8, 136u8, 140u8, 44u8, 101u8, 202u8, 151u8, 12u8, 76u8, 26u8, 42u8, 142u8, 178u8, 55u8, 112u8, 254u8, 57u8, 192u8, 39u8, 11u8, 31u8, 149u8, 81u8, 164u8, 56u8, 35u8, 62u8, 9u8, 153u8, 202u8, 73u8, 151u8, 33u8, 81u8, 119u8, 100u8, 29u8, 105u8, 65u8, 91u8, 191u8, 9u8, 15u8, 50u8, 86u8, 226u8, 223u8, 172u8, 127u8, 181u8, 242u8, 49u8, 178u8, 109u8, 106u8, 34u8, 37u8, 31u8, 3u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 86u8, 171u8, 102u8, 229u8, 201u8, 61u8, 216u8, 222u8, 166u8, 194u8, 138u8, 122u8, 129u8, 122u8, 157u8, 29u8, 60u8, 162u8, 33u8, 105u8, 104u8, 199u8, 119u8, 150u8, 99u8, 138u8, 140u8, 66u8, 51u8, 244u8, 142u8, 34u8, 241u8, 86u8, 175u8, 167u8, 70u8, 142u8, 41u8, 222u8, 42u8, 19u8, 203u8, 145u8, 146u8, 220u8, 243u8, 75u8, 219u8, 44u8, 140u8, 170u8, 58u8, 183u8, 95u8, 130u8, 13u8, 186u8, 31u8, 0u8, 109u8, 26u8, 180u8, 14u8, 9u8, 151u8, 253u8, 48u8, 138u8, 235u8, 173u8, 74u8, 69u8, 59u8, 217u8, 230u8, 138u8, 209u8, 28u8, 197u8, 216u8, 126u8, 127u8, 254u8, 216u8, 164u8, 201u8, 24u8, 104u8, 31u8, 60u8, 42u8, 105u8, 100u8, 200u8, 16u8];
        
        let ctx = test_scenario::ctx(&mut scenario);
        proximity::init_verifying_key(&server_cap, vk_bytes, ctx);
        
        test_scenario::return_to_sender(&scenario, server_cap);
    };

    // Create commitment
    scenario.next_tx(@0x1);
    {
        let server_cap = test_scenario::take_from_sender<proximity::ServerCap>(&scenario);
        let commitment_bytes = vector[30u8, 30u8, 219u8, 114u8, 159u8, 179u8, 170u8, 234u8, 98u8, 71u8, 60u8, 126u8, 131u8, 44u8, 69u8, 89u8, 147u8, 254u8, 101u8, 171u8, 191u8, 13u8, 178u8, 13u8, 210u8, 140u8, 12u8, 48u8, 206u8, 119u8, 224u8, 43u8];
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
        let proof_bytes = vector[12u8, 171u8, 22u8, 202u8, 201u8, 57u8, 198u8, 101u8, 117u8, 217u8, 32u8, 40u8, 146u8, 37u8, 241u8, 144u8, 89u8, 91u8, 77u8, 3u8, 155u8, 120u8, 64u8, 57u8, 71u8, 76u8, 146u8, 249u8, 8u8, 129u8, 136u8, 148u8, 141u8, 73u8, 144u8, 28u8, 5u8, 8u8, 251u8, 119u8, 78u8, 72u8, 96u8, 197u8, 233u8, 11u8, 93u8, 225u8, 69u8, 125u8, 47u8, 90u8, 148u8, 197u8, 237u8, 122u8, 29u8, 224u8, 241u8, 116u8, 239u8, 145u8, 179u8, 28u8, 83u8, 71u8, 51u8, 147u8, 197u8, 25u8, 62u8, 231u8, 127u8, 64u8, 22u8, 242u8, 121u8, 129u8, 30u8, 139u8, 25u8, 109u8, 46u8, 161u8, 171u8, 223u8, 219u8, 108u8, 210u8, 33u8, 124u8, 164u8, 66u8, 132u8, 176u8, 20u8, 197u8, 176u8, 19u8, 185u8, 123u8, 51u8, 35u8, 60u8, 17u8, 234u8, 142u8, 121u8, 171u8, 7u8, 149u8, 229u8, 204u8, 42u8, 204u8, 121u8, 217u8, 155u8, 125u8, 83u8, 180u8, 12u8, 241u8, 66u8, 255u8, 204u8, 206u8, 158u8];
        let public_inputs = vector[30u8, 30u8, 219u8, 114u8, 159u8, 179u8, 170u8, 234u8, 98u8, 71u8, 60u8, 126u8, 131u8, 44u8, 69u8, 89u8, 108u8, 254u8, 101u8, 171u8, 191u8, 13u8, 178u8, 13u8, 210u8, 140u8, 12u8, 48u8, 206u8, 119u8, 224u8, 43u8, 0u8, 225u8, 245u8, 5u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8]; // Wrong public inputs
        
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
        let vk_bytes = vector[229u8, 122u8, 162u8, 112u8, 40u8, 77u8, 47u8, 228u8, 92u8, 145u8, 25u8, 175u8, 109u8, 140u8, 97u8, 125u8, 216u8, 110u8, 240u8, 107u8, 29u8, 83u8, 241u8, 39u8, 191u8, 150u8, 18u8, 254u8, 76u8, 120u8, 163u8, 142u8, 136u8, 229u8, 4u8, 112u8, 29u8, 104u8, 157u8, 254u8, 17u8, 102u8, 250u8, 144u8, 132u8, 87u8, 69u8, 126u8, 255u8, 179u8, 64u8, 67u8, 127u8, 236u8, 61u8, 225u8, 54u8, 234u8, 26u8, 10u8, 58u8, 154u8, 92u8, 10u8, 250u8, 241u8, 0u8, 221u8, 56u8, 82u8, 235u8, 21u8, 8u8, 35u8, 138u8, 176u8, 88u8, 192u8, 141u8, 255u8, 17u8, 153u8, 45u8, 189u8, 195u8, 228u8, 176u8, 228u8, 120u8, 146u8, 59u8, 82u8, 207u8, 59u8, 188u8, 43u8, 147u8, 88u8, 162u8, 103u8, 147u8, 14u8, 133u8, 167u8, 53u8, 65u8, 55u8, 49u8, 45u8, 171u8, 5u8, 5u8, 123u8, 154u8, 240u8, 52u8, 208u8, 216u8, 151u8, 254u8, 68u8, 133u8, 19u8, 21u8, 126u8, 41u8, 197u8, 43u8, 98u8, 164u8, 11u8, 82u8, 82u8, 244u8, 195u8, 1u8, 186u8, 40u8, 71u8, 142u8, 179u8, 233u8, 70u8, 119u8, 120u8, 140u8, 59u8, 162u8, 25u8, 56u8, 176u8, 3u8, 209u8, 130u8, 85u8, 28u8, 118u8, 96u8, 5u8, 141u8, 183u8, 65u8, 216u8, 47u8, 112u8, 8u8, 105u8, 136u8, 140u8, 44u8, 101u8, 202u8, 151u8, 12u8, 76u8, 26u8, 42u8, 142u8, 178u8, 55u8, 112u8, 254u8, 57u8, 192u8, 39u8, 11u8, 31u8, 149u8, 81u8, 164u8, 56u8, 35u8, 62u8, 9u8, 153u8, 202u8, 73u8, 151u8, 33u8, 81u8, 119u8, 100u8, 29u8, 105u8, 65u8, 91u8, 191u8, 9u8, 15u8, 50u8, 86u8, 226u8, 223u8, 172u8, 127u8, 181u8, 242u8, 49u8, 178u8, 109u8, 106u8, 34u8, 37u8, 31u8, 3u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 86u8, 171u8, 102u8, 229u8, 201u8, 61u8, 216u8, 222u8, 166u8, 194u8, 138u8, 122u8, 129u8, 122u8, 157u8, 29u8, 60u8, 162u8, 33u8, 105u8, 104u8, 199u8, 119u8, 150u8, 99u8, 138u8, 140u8, 66u8, 51u8, 244u8, 142u8, 34u8, 241u8, 86u8, 175u8, 167u8, 70u8, 142u8, 41u8, 222u8, 42u8, 19u8, 203u8, 145u8, 146u8, 220u8, 243u8, 75u8, 219u8, 44u8, 140u8, 170u8, 58u8, 183u8, 95u8, 130u8, 13u8, 186u8, 31u8, 0u8, 109u8, 26u8, 180u8, 14u8, 9u8, 151u8, 253u8, 48u8, 138u8, 235u8, 173u8, 74u8, 69u8, 59u8, 217u8, 230u8, 138u8, 209u8, 28u8, 197u8, 216u8, 126u8, 127u8, 254u8, 216u8, 164u8, 201u8, 24u8, 104u8, 31u8, 60u8, 42u8, 105u8, 100u8, 200u8, 16u8];
        
        let ctx = test_scenario::ctx(&mut scenario);
        proximity::init_verifying_key(&server_cap, vk_bytes, ctx);
        
        test_scenario::return_to_sender(&scenario, server_cap);
    };

    // Create commitment with different coordinates
    scenario.next_tx(@0x1);
    {
        let server_cap = test_scenario::take_from_sender<proximity::ServerCap>(&scenario);
        let commitment_bytes = vector[91u8, 82u8, 248u8, 145u8, 30u8, 253u8, 237u8, 182u8, 222u8, 102u8, 200u8, 166u8, 17u8, 64u8, 227u8, 142u8, 153u8, 131u8, 173u8, 108u8, 49u8, 254u8, 135u8, 32u8, 204u8, 219u8, 217u8, 62u8, 121u8, 101u8, 194u8, 6u8]; // Different Poseidon commitment hash (32 bytes)
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
        let proof_bytes = vector[52u8, 251u8, 83u8, 100u8, 232u8, 42u8, 62u8, 202u8, 225u8, 32u8, 176u8, 88u8, 43u8, 24u8, 42u8, 88u8, 137u8, 102u8, 108u8, 107u8, 2u8, 53u8, 62u8, 95u8, 234u8, 56u8, 225u8, 49u8, 69u8, 125u8, 56u8, 167u8, 81u8, 17u8, 166u8, 120u8, 243u8, 60u8, 104u8, 186u8, 71u8, 222u8, 209u8, 229u8, 108u8, 208u8, 168u8, 222u8, 20u8, 111u8, 181u8, 197u8, 126u8, 20u8, 19u8, 92u8, 4u8, 218u8, 203u8, 210u8, 147u8, 56u8, 49u8, 25u8, 217u8, 3u8, 131u8, 90u8, 32u8, 66u8, 1u8, 21u8, 134u8, 152u8, 52u8, 146u8, 166u8, 226u8, 115u8, 199u8, 163u8, 62u8, 137u8, 87u8, 30u8, 75u8, 16u8, 150u8, 192u8, 200u8, 136u8, 49u8, 66u8, 182u8, 194u8, 6u8, 59u8, 42u8, 118u8, 163u8, 136u8, 38u8, 46u8, 150u8, 151u8, 142u8, 168u8, 245u8, 60u8, 104u8, 187u8, 206u8, 25u8, 230u8, 234u8, 141u8, 3u8, 109u8, 5u8, 152u8, 106u8, 155u8, 174u8, 241u8, 112u8, 195u8, 6u8, 3u8];
        let public_inputs = vector[91u8, 82u8, 248u8, 145u8, 30u8, 253u8, 237u8, 182u8, 222u8, 102u8, 200u8, 166u8, 17u8, 64u8, 227u8, 142u8, 153u8, 131u8, 173u8, 108u8, 49u8, 254u8, 135u8, 32u8, 204u8, 219u8, 217u8, 62u8, 121u8, 101u8, 194u8, 6u8, 0u8, 225u8, 245u8, 5u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8];
        
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
fun test_invalid_invesed_sign_value_coordinates_fails() {
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
        let vk_bytes = vector[229u8, 122u8, 162u8, 112u8, 40u8, 77u8, 47u8, 228u8, 92u8, 145u8, 25u8, 175u8, 109u8, 140u8, 97u8, 125u8, 216u8, 110u8, 240u8, 107u8, 29u8, 83u8, 241u8, 39u8, 191u8, 150u8, 18u8, 254u8, 76u8, 120u8, 163u8, 142u8, 136u8, 229u8, 4u8, 112u8, 29u8, 104u8, 157u8, 254u8, 17u8, 102u8, 250u8, 144u8, 132u8, 87u8, 69u8, 126u8, 255u8, 179u8, 64u8, 67u8, 127u8, 236u8, 61u8, 225u8, 54u8, 234u8, 26u8, 10u8, 58u8, 154u8, 92u8, 10u8, 250u8, 241u8, 0u8, 221u8, 56u8, 82u8, 235u8, 21u8, 8u8, 35u8, 138u8, 176u8, 88u8, 192u8, 141u8, 255u8, 17u8, 153u8, 45u8, 189u8, 195u8, 228u8, 176u8, 228u8, 120u8, 146u8, 59u8, 82u8, 207u8, 59u8, 188u8, 43u8, 147u8, 88u8, 162u8, 103u8, 147u8, 14u8, 133u8, 167u8, 53u8, 65u8, 55u8, 49u8, 45u8, 171u8, 5u8, 5u8, 123u8, 154u8, 240u8, 52u8, 208u8, 216u8, 151u8, 254u8, 68u8, 133u8, 19u8, 21u8, 126u8, 41u8, 197u8, 43u8, 98u8, 164u8, 11u8, 82u8, 82u8, 244u8, 195u8, 1u8, 186u8, 40u8, 71u8, 142u8, 179u8, 233u8, 70u8, 119u8, 120u8, 140u8, 59u8, 162u8, 25u8, 56u8, 176u8, 3u8, 209u8, 130u8, 85u8, 28u8, 118u8, 96u8, 5u8, 141u8, 183u8, 65u8, 216u8, 47u8, 112u8, 8u8, 105u8, 136u8, 140u8, 44u8, 101u8, 202u8, 151u8, 12u8, 76u8, 26u8, 42u8, 142u8, 178u8, 55u8, 112u8, 254u8, 57u8, 192u8, 39u8, 11u8, 31u8, 149u8, 81u8, 164u8, 56u8, 35u8, 62u8, 9u8, 153u8, 202u8, 73u8, 151u8, 33u8, 81u8, 119u8, 100u8, 29u8, 105u8, 65u8, 91u8, 191u8, 9u8, 15u8, 50u8, 86u8, 226u8, 223u8, 172u8, 127u8, 181u8, 242u8, 49u8, 178u8, 109u8, 106u8, 34u8, 37u8, 31u8, 3u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 86u8, 171u8, 102u8, 229u8, 201u8, 61u8, 216u8, 222u8, 166u8, 194u8, 138u8, 122u8, 129u8, 122u8, 157u8, 29u8, 60u8, 162u8, 33u8, 105u8, 104u8, 199u8, 119u8, 150u8, 99u8, 138u8, 140u8, 66u8, 51u8, 244u8, 142u8, 34u8, 241u8, 86u8, 175u8, 167u8, 70u8, 142u8, 41u8, 222u8, 42u8, 19u8, 203u8, 145u8, 146u8, 220u8, 243u8, 75u8, 219u8, 44u8, 140u8, 170u8, 58u8, 183u8, 95u8, 130u8, 13u8, 186u8, 31u8, 0u8, 109u8, 26u8, 180u8, 14u8, 9u8, 151u8, 253u8, 48u8, 138u8, 235u8, 173u8, 74u8, 69u8, 59u8, 217u8, 230u8, 138u8, 209u8, 28u8, 197u8, 216u8, 126u8, 127u8, 254u8, 216u8, 164u8, 201u8, 24u8, 104u8, 31u8, 60u8, 42u8, 105u8, 100u8, 200u8, 16u8];
        
        let ctx = test_scenario::ctx(&mut scenario);
        proximity::init_verifying_key(&server_cap, vk_bytes, ctx);
        
        test_scenario::return_to_sender(&scenario, server_cap);
    };

    // Create commitment with absolute value coordinates
    scenario.next_tx(@0x1);
    {
        let server_cap = test_scenario::take_from_sender<proximity::ServerCap>(&scenario);
        let commitment_bytes = vector[166u8, 150u8, 189u8, 222u8, 16u8, 179u8, 131u8, 80u8, 113u8, 13u8, 4u8, 53u8, 7u8, 73u8, 117u8, 118u8, 92u8, 43u8, 11u8, 0u8, 133u8, 232u8, 95u8, 250u8, 108u8, 59u8, 224u8, 13u8, 110u8, 152u8, 16u8, 39u8]; // Absolute value Poseidon commitment hash (32 bytes)
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
        let proof_bytes = vector[12u8, 171u8, 22u8, 202u8, 201u8, 57u8, 198u8, 101u8, 117u8, 217u8, 32u8, 40u8, 146u8, 37u8, 241u8, 144u8, 89u8, 91u8, 77u8, 3u8, 155u8, 120u8, 64u8, 57u8, 71u8, 76u8, 146u8, 249u8, 8u8, 129u8, 136u8, 148u8, 141u8, 73u8, 144u8, 28u8, 5u8, 8u8, 251u8, 119u8, 78u8, 72u8, 96u8, 197u8, 233u8, 11u8, 93u8, 225u8, 69u8, 125u8, 47u8, 90u8, 148u8, 197u8, 237u8, 122u8, 29u8, 224u8, 241u8, 116u8, 239u8, 145u8, 179u8, 28u8, 83u8, 71u8, 51u8, 147u8, 197u8, 25u8, 62u8, 231u8, 127u8, 64u8, 22u8, 242u8, 121u8, 129u8, 30u8, 139u8, 25u8, 109u8, 46u8, 161u8, 171u8, 223u8, 219u8, 108u8, 210u8, 33u8, 124u8, 164u8, 66u8, 132u8, 176u8, 20u8, 197u8, 176u8, 19u8, 185u8, 123u8, 51u8, 35u8, 60u8, 17u8, 234u8, 142u8, 121u8, 171u8, 7u8, 149u8, 229u8, 204u8, 42u8, 204u8, 121u8, 217u8, 155u8, 125u8, 83u8, 180u8, 12u8, 241u8, 66u8, 255u8, 204u8, 206u8, 158u8];
        let public_inputs = vector[30u8, 30u8, 219u8, 114u8, 159u8, 179u8, 170u8, 234u8, 98u8, 71u8, 60u8, 126u8, 131u8, 44u8, 69u8, 89u8, 147u8, 254u8, 101u8, 171u8, 191u8, 13u8, 178u8, 13u8, 210u8, 140u8, 12u8, 48u8, 206u8, 119u8, 224u8, 43u8, 0u8, 225u8, 245u8, 5u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8];
        
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
