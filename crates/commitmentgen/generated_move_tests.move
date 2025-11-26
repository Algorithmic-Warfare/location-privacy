
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
        let vk_bytes = vector[83u8, 4u8, 216u8, 252u8, 25u8, 246u8, 102u8, 57u8, 184u8, 218u8, 47u8, 146u8, 198u8, 124u8, 70u8, 97u8, 247u8, 161u8, 166u8, 179u8, 33u8, 105u8, 55u8, 21u8, 43u8, 139u8, 27u8, 182u8, 3u8, 87u8, 65u8, 132u8, 65u8, 155u8, 58u8, 20u8, 63u8, 176u8, 149u8, 16u8, 64u8, 71u8, 129u8, 78u8, 183u8, 204u8, 126u8, 161u8, 149u8, 25u8, 177u8, 98u8, 168u8, 40u8, 190u8, 35u8, 235u8, 183u8, 123u8, 138u8, 228u8, 178u8, 183u8, 19u8, 83u8, 29u8, 245u8, 1u8, 171u8, 165u8, 116u8, 114u8, 148u8, 120u8, 225u8, 251u8, 54u8, 51u8, 17u8, 202u8, 60u8, 110u8, 255u8, 41u8, 104u8, 215u8, 176u8, 59u8, 160u8, 0u8, 110u8, 156u8, 97u8, 164u8, 2u8, 27u8, 252u8, 73u8, 114u8, 153u8, 90u8, 120u8, 120u8, 87u8, 173u8, 100u8, 211u8, 255u8, 254u8, 49u8, 163u8, 47u8, 179u8, 247u8, 42u8, 206u8, 44u8, 48u8, 129u8, 97u8, 99u8, 235u8, 133u8, 54u8, 205u8, 3u8, 76u8, 37u8, 30u8, 107u8, 2u8, 164u8, 66u8, 66u8, 122u8, 116u8, 235u8, 243u8, 59u8, 130u8, 173u8, 179u8, 45u8, 71u8, 119u8, 81u8, 220u8, 98u8, 205u8, 241u8, 3u8, 37u8, 201u8, 199u8, 202u8, 241u8, 89u8, 233u8, 107u8, 41u8, 210u8, 147u8, 255u8, 135u8, 35u8, 119u8, 205u8, 112u8, 213u8, 40u8, 220u8, 255u8, 24u8, 133u8, 115u8, 161u8, 207u8, 235u8, 224u8, 159u8, 98u8, 102u8, 44u8, 53u8, 247u8, 15u8, 72u8, 29u8, 2u8, 157u8, 16u8, 19u8, 78u8, 90u8, 139u8, 89u8, 87u8, 203u8, 27u8, 0u8, 244u8, 62u8, 38u8, 8u8, 243u8, 217u8, 238u8, 13u8, 31u8, 164u8, 224u8, 44u8, 217u8, 123u8, 241u8, 91u8, 226u8, 152u8, 83u8, 80u8, 94u8, 192u8, 162u8, 6u8, 3u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 6u8, 3u8, 21u8, 166u8, 215u8, 205u8, 158u8, 88u8, 135u8, 22u8, 228u8, 191u8, 44u8, 64u8, 254u8, 160u8, 19u8, 66u8, 197u8, 1u8, 170u8, 36u8, 172u8, 45u8, 45u8, 143u8, 115u8, 108u8, 77u8, 236u8, 251u8, 9u8, 151u8, 91u8, 97u8, 96u8, 36u8, 38u8, 26u8, 133u8, 103u8, 109u8, 44u8, 169u8, 143u8, 108u8, 61u8, 64u8, 167u8, 136u8, 107u8, 191u8, 224u8, 153u8, 248u8, 204u8, 92u8, 130u8, 138u8, 47u8, 16u8, 141u8, 62u8, 171u8, 20u8, 134u8, 73u8, 133u8, 59u8, 24u8, 123u8, 248u8, 156u8, 219u8, 48u8, 152u8, 190u8, 72u8, 245u8, 90u8, 117u8, 5u8, 234u8, 116u8, 174u8, 64u8, 108u8, 37u8, 49u8, 14u8, 98u8, 123u8, 217u8, 162u8, 27u8, 163u8]; // Canonical verifying key (328 bytes)
        
        let ctx = test_scenario::ctx(&mut scenario);
        proximity::init_verifying_key(&server_cap, vk_bytes, ctx);
        
        test_scenario::return_to_sender(&scenario, server_cap);
    };

    // Create commitment (Poseidon hash - 32 bytes)
    scenario.next_tx(@0x1);
    {
        let server_cap = test_scenario::take_from_sender<proximity::ServerCap>(&scenario);
        let commitment_bytes = vector[242u8, 103u8, 23u8, 88u8, 12u8, 96u8, 149u8, 7u8, 157u8, 65u8, 33u8, 229u8, 8u8, 31u8, 71u8, 135u8, 53u8, 164u8, 180u8, 172u8, 145u8, 46u8, 85u8, 54u8, 26u8, 90u8, 194u8, 44u8, 196u8, 190u8, 74u8, 29u8]; // Poseidon hash (32 bytes)
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
        let proof_bytes = vector[98u8, 83u8, 68u8, 181u8, 54u8, 124u8, 6u8, 188u8, 121u8, 253u8, 92u8, 83u8, 89u8, 55u8, 4u8, 162u8, 79u8, 197u8, 97u8, 42u8, 66u8, 229u8, 101u8, 64u8, 81u8, 118u8, 44u8, 43u8, 141u8, 246u8, 110u8, 46u8, 185u8, 39u8, 200u8, 130u8, 178u8, 75u8, 40u8, 143u8, 8u8, 63u8, 121u8, 245u8, 145u8, 92u8, 208u8, 131u8, 220u8, 121u8, 251u8, 242u8, 198u8, 178u8, 61u8, 230u8, 198u8, 89u8, 240u8, 164u8, 248u8, 159u8, 205u8, 5u8, 172u8, 102u8, 34u8, 127u8, 126u8, 185u8, 142u8, 94u8, 108u8, 48u8, 62u8, 200u8, 158u8, 54u8, 144u8, 8u8, 27u8, 146u8, 121u8, 154u8, 118u8, 82u8, 90u8, 192u8, 237u8, 30u8, 164u8, 30u8, 52u8, 221u8, 244u8, 17u8, 118u8, 126u8, 30u8, 76u8, 145u8, 217u8, 204u8, 197u8, 41u8, 221u8, 176u8, 60u8, 80u8, 62u8, 47u8, 117u8, 3u8, 158u8, 67u8, 135u8, 4u8, 113u8, 112u8, 135u8, 178u8, 13u8, 7u8, 231u8, 168u8, 170u8, 83u8, 138u8];
        let public_inputs = vector[242u8, 103u8, 23u8, 88u8, 12u8, 96u8, 149u8, 7u8, 157u8, 65u8, 33u8, 229u8, 8u8, 31u8, 71u8, 135u8, 53u8, 164u8, 180u8, 172u8, 145u8, 46u8, 85u8, 54u8, 26u8, 90u8, 194u8, 44u8, 196u8, 190u8, 74u8, 29u8, 0u8, 225u8, 245u8, 5u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8]; // [commitment_hash, max_distance_squared] (64 bytes total)
        
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
        let vk_bytes = vector[83u8, 4u8, 216u8, 252u8, 25u8, 246u8, 102u8, 57u8, 184u8, 218u8, 47u8, 146u8, 198u8, 124u8, 70u8, 97u8, 247u8, 161u8, 166u8, 179u8, 33u8, 105u8, 55u8, 21u8, 43u8, 139u8, 27u8, 182u8, 3u8, 87u8, 65u8, 132u8, 65u8, 155u8, 58u8, 20u8, 63u8, 176u8, 149u8, 16u8, 64u8, 71u8, 129u8, 78u8, 183u8, 204u8, 126u8, 161u8, 149u8, 25u8, 177u8, 98u8, 168u8, 40u8, 190u8, 35u8, 235u8, 183u8, 123u8, 138u8, 228u8, 178u8, 183u8, 19u8, 83u8, 29u8, 245u8, 1u8, 171u8, 165u8, 116u8, 114u8, 148u8, 120u8, 225u8, 251u8, 54u8, 51u8, 17u8, 202u8, 60u8, 110u8, 255u8, 41u8, 104u8, 215u8, 176u8, 59u8, 160u8, 0u8, 110u8, 156u8, 97u8, 164u8, 2u8, 27u8, 252u8, 73u8, 114u8, 153u8, 90u8, 120u8, 120u8, 87u8, 173u8, 100u8, 211u8, 255u8, 254u8, 49u8, 163u8, 47u8, 179u8, 247u8, 42u8, 206u8, 44u8, 48u8, 129u8, 97u8, 99u8, 235u8, 133u8, 54u8, 205u8, 3u8, 76u8, 37u8, 30u8, 107u8, 2u8, 164u8, 66u8, 66u8, 122u8, 116u8, 235u8, 243u8, 59u8, 130u8, 173u8, 179u8, 45u8, 71u8, 119u8, 81u8, 220u8, 98u8, 205u8, 241u8, 3u8, 37u8, 201u8, 199u8, 202u8, 241u8, 89u8, 233u8, 107u8, 41u8, 210u8, 147u8, 255u8, 135u8, 35u8, 119u8, 205u8, 112u8, 213u8, 40u8, 220u8, 255u8, 24u8, 133u8, 115u8, 161u8, 207u8, 235u8, 224u8, 159u8, 98u8, 102u8, 44u8, 53u8, 247u8, 15u8, 72u8, 29u8, 2u8, 157u8, 16u8, 19u8, 78u8, 90u8, 139u8, 89u8, 87u8, 203u8, 27u8, 0u8, 244u8, 62u8, 38u8, 8u8, 243u8, 217u8, 238u8, 13u8, 31u8, 164u8, 224u8, 44u8, 217u8, 123u8, 241u8, 91u8, 226u8, 152u8, 83u8, 80u8, 94u8, 192u8, 162u8, 6u8, 3u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 6u8, 3u8, 21u8, 166u8, 215u8, 205u8, 158u8, 88u8, 135u8, 22u8, 228u8, 191u8, 44u8, 64u8, 254u8, 160u8, 19u8, 66u8, 197u8, 1u8, 170u8, 36u8, 172u8, 45u8, 45u8, 143u8, 115u8, 108u8, 77u8, 236u8, 251u8, 9u8, 151u8, 91u8, 97u8, 96u8, 36u8, 38u8, 26u8, 133u8, 103u8, 109u8, 44u8, 169u8, 143u8, 108u8, 61u8, 64u8, 167u8, 136u8, 107u8, 191u8, 224u8, 153u8, 248u8, 204u8, 92u8, 130u8, 138u8, 47u8, 16u8, 141u8, 62u8, 171u8, 20u8, 134u8, 73u8, 133u8, 59u8, 24u8, 123u8, 248u8, 156u8, 219u8, 48u8, 152u8, 190u8, 72u8, 245u8, 90u8, 117u8, 5u8, 234u8, 116u8, 174u8, 64u8, 108u8, 37u8, 49u8, 14u8, 98u8, 123u8, 217u8, 162u8, 27u8, 163u8];
        
        let ctx = test_scenario::ctx(&mut scenario);
        proximity::init_verifying_key(&server_cap, vk_bytes, ctx);
        
        test_scenario::return_to_sender(&scenario, server_cap);
    };

    // Create commitment
    scenario.next_tx(@0x1);
    {
        let server_cap = test_scenario::take_from_sender<proximity::ServerCap>(&scenario);
        let commitment_bytes = vector[242u8, 103u8, 23u8, 88u8, 12u8, 96u8, 149u8, 7u8, 157u8, 65u8, 33u8, 229u8, 8u8, 31u8, 71u8, 135u8, 53u8, 164u8, 180u8, 172u8, 145u8, 46u8, 85u8, 54u8, 26u8, 90u8, 194u8, 44u8, 196u8, 190u8, 74u8, 29u8];
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
        let proof_bytes = vector[98u8, 83u8, 68u8, 181u8, 54u8, 124u8, 6u8, 188u8, 121u8, 253u8, 163u8, 83u8, 89u8, 55u8, 4u8, 162u8, 79u8, 197u8, 97u8, 42u8, 66u8, 229u8, 101u8, 64u8, 81u8, 118u8, 44u8, 43u8, 141u8, 246u8, 110u8, 46u8, 185u8, 39u8, 200u8, 130u8, 178u8, 75u8, 40u8, 143u8, 8u8, 63u8, 121u8, 245u8, 145u8, 92u8, 208u8, 131u8, 220u8, 121u8, 251u8, 242u8, 198u8, 178u8, 61u8, 230u8, 198u8, 89u8, 240u8, 164u8, 248u8, 159u8, 205u8, 5u8, 172u8, 102u8, 34u8, 127u8, 126u8, 185u8, 142u8, 94u8, 108u8, 48u8, 62u8, 200u8, 158u8, 54u8, 144u8, 8u8, 27u8, 146u8, 121u8, 154u8, 118u8, 82u8, 90u8, 192u8, 237u8, 30u8, 164u8, 30u8, 52u8, 221u8, 244u8, 17u8, 118u8, 126u8, 30u8, 76u8, 145u8, 217u8, 204u8, 197u8, 41u8, 221u8, 176u8, 60u8, 80u8, 62u8, 47u8, 117u8, 3u8, 158u8, 67u8, 135u8, 4u8, 113u8, 112u8, 135u8, 178u8, 13u8, 7u8, 231u8, 168u8, 170u8, 83u8, 138u8]; // Corrupted proof bytes
        let public_inputs = vector[242u8, 103u8, 23u8, 88u8, 12u8, 96u8, 149u8, 7u8, 157u8, 65u8, 33u8, 229u8, 8u8, 31u8, 71u8, 135u8, 53u8, 164u8, 180u8, 172u8, 145u8, 46u8, 85u8, 54u8, 26u8, 90u8, 194u8, 44u8, 196u8, 190u8, 74u8, 29u8, 0u8, 225u8, 245u8, 5u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8];
        
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
        let wrong_vk_bytes = vector[20u8, 22u8, 47u8, 103u8, 99u8, 184u8, 207u8, 107u8, 181u8, 27u8, 5u8, 89u8, 206u8, 65u8, 173u8, 104u8, 149u8, 248u8, 53u8, 215u8, 93u8, 7u8, 218u8, 41u8, 44u8, 77u8, 106u8, 235u8, 252u8, 77u8, 224u8, 158u8, 25u8, 254u8, 189u8, 69u8, 16u8, 241u8, 13u8, 218u8, 231u8, 184u8, 45u8, 91u8, 3u8, 130u8, 242u8, 126u8, 115u8, 248u8, 28u8, 103u8, 53u8, 120u8, 33u8, 247u8, 100u8, 49u8, 70u8, 223u8, 111u8, 34u8, 52u8, 19u8, 103u8, 127u8, 218u8, 233u8, 84u8, 152u8, 70u8, 236u8, 203u8, 61u8, 118u8, 41u8, 155u8, 190u8, 101u8, 101u8, 120u8, 53u8, 199u8, 61u8, 128u8, 12u8, 50u8, 130u8, 240u8, 23u8, 59u8, 22u8, 234u8, 40u8, 24u8, 149u8, 122u8, 175u8, 75u8, 48u8, 4u8, 123u8, 3u8, 35u8, 84u8, 235u8, 126u8, 120u8, 78u8, 1u8, 215u8, 73u8, 31u8, 153u8, 253u8, 225u8, 220u8, 220u8, 246u8, 113u8, 42u8, 173u8, 151u8, 140u8, 153u8, 57u8, 190u8, 42u8, 183u8, 111u8, 118u8, 215u8, 57u8, 218u8, 45u8, 235u8, 212u8, 152u8, 197u8, 152u8, 122u8, 4u8, 201u8, 130u8, 168u8, 208u8, 217u8, 19u8, 155u8, 73u8, 240u8, 13u8, 53u8, 237u8, 70u8, 26u8, 251u8, 7u8, 100u8, 23u8, 213u8, 251u8, 145u8, 179u8, 152u8, 77u8, 63u8, 142u8, 234u8, 255u8, 134u8, 198u8, 252u8, 59u8, 37u8, 53u8, 121u8, 37u8, 15u8, 219u8, 134u8, 90u8, 203u8, 252u8, 198u8, 93u8, 137u8, 144u8, 120u8, 86u8, 171u8, 2u8, 3u8, 158u8, 157u8, 9u8, 35u8, 23u8, 163u8, 179u8, 169u8, 49u8, 148u8, 210u8, 32u8, 123u8, 127u8, 22u8, 68u8, 59u8, 168u8, 87u8, 102u8, 75u8, 221u8, 216u8, 120u8, 211u8, 230u8, 31u8, 251u8, 229u8, 62u8, 144u8, 3u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 126u8, 77u8, 200u8, 245u8, 138u8, 17u8, 112u8, 148u8, 41u8, 51u8, 21u8, 22u8, 136u8, 5u8, 85u8, 213u8, 48u8, 119u8, 115u8, 92u8, 180u8, 139u8, 185u8, 11u8, 68u8, 203u8, 138u8, 26u8, 206u8, 96u8, 171u8, 19u8, 47u8, 178u8, 127u8, 102u8, 183u8, 128u8, 195u8, 3u8, 73u8, 32u8, 93u8, 32u8, 222u8, 5u8, 254u8, 69u8, 224u8, 147u8, 37u8, 185u8, 249u8, 134u8, 88u8, 250u8, 196u8, 74u8, 15u8, 53u8, 85u8, 210u8, 104u8, 145u8, 165u8, 16u8, 91u8, 29u8, 9u8, 100u8, 69u8, 230u8, 208u8, 255u8, 132u8, 113u8, 139u8, 97u8, 31u8, 61u8, 80u8, 31u8, 127u8, 181u8, 198u8, 221u8, 245u8, 210u8, 74u8, 224u8, 11u8, 78u8, 209u8, 5u8, 237u8, 136u8]; // Wrong VK bytes (from different trusted setup)
        
        let ctx = test_scenario::ctx(&mut scenario);
        proximity::init_verifying_key(&server_cap, wrong_vk_bytes, ctx);
        
        test_scenario::return_to_sender(&scenario, server_cap);
    };

    // Create commitment
    scenario.next_tx(@0x1);
    {
        let server_cap = test_scenario::take_from_sender<proximity::ServerCap>(&scenario);
        let commitment_bytes = vector[242u8, 103u8, 23u8, 88u8, 12u8, 96u8, 149u8, 7u8, 157u8, 65u8, 33u8, 229u8, 8u8, 31u8, 71u8, 135u8, 53u8, 164u8, 180u8, 172u8, 145u8, 46u8, 85u8, 54u8, 26u8, 90u8, 194u8, 44u8, 196u8, 190u8, 74u8, 29u8];
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
        let proof_bytes = vector[98u8, 83u8, 68u8, 181u8, 54u8, 124u8, 6u8, 188u8, 121u8, 253u8, 92u8, 83u8, 89u8, 55u8, 4u8, 162u8, 79u8, 197u8, 97u8, 42u8, 66u8, 229u8, 101u8, 64u8, 81u8, 118u8, 44u8, 43u8, 141u8, 246u8, 110u8, 46u8, 185u8, 39u8, 200u8, 130u8, 178u8, 75u8, 40u8, 143u8, 8u8, 63u8, 121u8, 245u8, 145u8, 92u8, 208u8, 131u8, 220u8, 121u8, 251u8, 242u8, 198u8, 178u8, 61u8, 230u8, 198u8, 89u8, 240u8, 164u8, 248u8, 159u8, 205u8, 5u8, 172u8, 102u8, 34u8, 127u8, 126u8, 185u8, 142u8, 94u8, 108u8, 48u8, 62u8, 200u8, 158u8, 54u8, 144u8, 8u8, 27u8, 146u8, 121u8, 154u8, 118u8, 82u8, 90u8, 192u8, 237u8, 30u8, 164u8, 30u8, 52u8, 221u8, 244u8, 17u8, 118u8, 126u8, 30u8, 76u8, 145u8, 217u8, 204u8, 197u8, 41u8, 221u8, 176u8, 60u8, 80u8, 62u8, 47u8, 117u8, 3u8, 158u8, 67u8, 135u8, 4u8, 113u8, 112u8, 135u8, 178u8, 13u8, 7u8, 231u8, 168u8, 170u8, 83u8, 138u8]; // Proof generated with correct VK
        let public_inputs = vector[242u8, 103u8, 23u8, 88u8, 12u8, 96u8, 149u8, 7u8, 157u8, 65u8, 33u8, 229u8, 8u8, 31u8, 71u8, 135u8, 53u8, 164u8, 180u8, 172u8, 145u8, 46u8, 85u8, 54u8, 26u8, 90u8, 194u8, 44u8, 196u8, 190u8, 74u8, 29u8, 0u8, 225u8, 245u8, 5u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8];
        
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
        let vk_bytes = vector[83u8, 4u8, 216u8, 252u8, 25u8, 246u8, 102u8, 57u8, 184u8, 218u8, 47u8, 146u8, 198u8, 124u8, 70u8, 97u8, 247u8, 161u8, 166u8, 179u8, 33u8, 105u8, 55u8, 21u8, 43u8, 139u8, 27u8, 182u8, 3u8, 87u8, 65u8, 132u8, 65u8, 155u8, 58u8, 20u8, 63u8, 176u8, 149u8, 16u8, 64u8, 71u8, 129u8, 78u8, 183u8, 204u8, 126u8, 161u8, 149u8, 25u8, 177u8, 98u8, 168u8, 40u8, 190u8, 35u8, 235u8, 183u8, 123u8, 138u8, 228u8, 178u8, 183u8, 19u8, 83u8, 29u8, 245u8, 1u8, 171u8, 165u8, 116u8, 114u8, 148u8, 120u8, 225u8, 251u8, 54u8, 51u8, 17u8, 202u8, 60u8, 110u8, 255u8, 41u8, 104u8, 215u8, 176u8, 59u8, 160u8, 0u8, 110u8, 156u8, 97u8, 164u8, 2u8, 27u8, 252u8, 73u8, 114u8, 153u8, 90u8, 120u8, 120u8, 87u8, 173u8, 100u8, 211u8, 255u8, 254u8, 49u8, 163u8, 47u8, 179u8, 247u8, 42u8, 206u8, 44u8, 48u8, 129u8, 97u8, 99u8, 235u8, 133u8, 54u8, 205u8, 3u8, 76u8, 37u8, 30u8, 107u8, 2u8, 164u8, 66u8, 66u8, 122u8, 116u8, 235u8, 243u8, 59u8, 130u8, 173u8, 179u8, 45u8, 71u8, 119u8, 81u8, 220u8, 98u8, 205u8, 241u8, 3u8, 37u8, 201u8, 199u8, 202u8, 241u8, 89u8, 233u8, 107u8, 41u8, 210u8, 147u8, 255u8, 135u8, 35u8, 119u8, 205u8, 112u8, 213u8, 40u8, 220u8, 255u8, 24u8, 133u8, 115u8, 161u8, 207u8, 235u8, 224u8, 159u8, 98u8, 102u8, 44u8, 53u8, 247u8, 15u8, 72u8, 29u8, 2u8, 157u8, 16u8, 19u8, 78u8, 90u8, 139u8, 89u8, 87u8, 203u8, 27u8, 0u8, 244u8, 62u8, 38u8, 8u8, 243u8, 217u8, 238u8, 13u8, 31u8, 164u8, 224u8, 44u8, 217u8, 123u8, 241u8, 91u8, 226u8, 152u8, 83u8, 80u8, 94u8, 192u8, 162u8, 6u8, 3u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 6u8, 3u8, 21u8, 166u8, 215u8, 205u8, 158u8, 88u8, 135u8, 22u8, 228u8, 191u8, 44u8, 64u8, 254u8, 160u8, 19u8, 66u8, 197u8, 1u8, 170u8, 36u8, 172u8, 45u8, 45u8, 143u8, 115u8, 108u8, 77u8, 236u8, 251u8, 9u8, 151u8, 91u8, 97u8, 96u8, 36u8, 38u8, 26u8, 133u8, 103u8, 109u8, 44u8, 169u8, 143u8, 108u8, 61u8, 64u8, 167u8, 136u8, 107u8, 191u8, 224u8, 153u8, 248u8, 204u8, 92u8, 130u8, 138u8, 47u8, 16u8, 141u8, 62u8, 171u8, 20u8, 134u8, 73u8, 133u8, 59u8, 24u8, 123u8, 248u8, 156u8, 219u8, 48u8, 152u8, 190u8, 72u8, 245u8, 90u8, 117u8, 5u8, 234u8, 116u8, 174u8, 64u8, 108u8, 37u8, 49u8, 14u8, 98u8, 123u8, 217u8, 162u8, 27u8, 163u8];
        
        let ctx = test_scenario::ctx(&mut scenario);
        proximity::init_verifying_key(&server_cap, vk_bytes, ctx);
        
        test_scenario::return_to_sender(&scenario, server_cap);
    };

    // Create commitment
    scenario.next_tx(@0x1);
    {
        let server_cap = test_scenario::take_from_sender<proximity::ServerCap>(&scenario);
        let commitment_bytes = vector[242u8, 103u8, 23u8, 88u8, 12u8, 96u8, 149u8, 7u8, 157u8, 65u8, 33u8, 229u8, 8u8, 31u8, 71u8, 135u8, 53u8, 164u8, 180u8, 172u8, 145u8, 46u8, 85u8, 54u8, 26u8, 90u8, 194u8, 44u8, 196u8, 190u8, 74u8, 29u8];
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
        let proof_bytes = vector[98u8, 83u8, 68u8, 181u8, 54u8, 124u8, 6u8, 188u8, 121u8, 253u8, 92u8, 83u8, 89u8, 55u8, 4u8, 162u8, 79u8, 197u8, 97u8, 42u8, 66u8, 229u8, 101u8, 64u8, 81u8, 118u8, 44u8, 43u8, 141u8, 246u8, 110u8, 46u8, 185u8, 39u8, 200u8, 130u8, 178u8, 75u8, 40u8, 143u8, 8u8, 63u8, 121u8, 245u8, 145u8, 92u8, 208u8, 131u8, 220u8, 121u8, 251u8, 242u8, 198u8, 178u8, 61u8, 230u8, 198u8, 89u8, 240u8, 164u8, 248u8, 159u8, 205u8, 5u8, 172u8, 102u8, 34u8, 127u8, 126u8, 185u8, 142u8, 94u8, 108u8, 48u8, 62u8, 200u8, 158u8, 54u8, 144u8, 8u8, 27u8, 146u8, 121u8, 154u8, 118u8, 82u8, 90u8, 192u8, 237u8, 30u8, 164u8, 30u8, 52u8, 221u8, 244u8, 17u8, 118u8, 126u8, 30u8, 76u8, 145u8, 217u8, 204u8, 197u8, 41u8, 221u8, 176u8, 60u8, 80u8, 62u8, 47u8, 117u8, 3u8, 158u8, 67u8, 135u8, 4u8, 113u8, 112u8, 135u8, 178u8, 13u8, 7u8, 231u8, 168u8, 170u8, 83u8, 138u8];
        let public_inputs = vector[242u8, 103u8, 23u8, 88u8, 12u8, 96u8, 149u8, 7u8, 157u8, 65u8, 33u8, 229u8, 8u8, 31u8, 71u8, 135u8, 202u8, 164u8, 180u8, 172u8, 145u8, 46u8, 85u8, 54u8, 26u8, 90u8, 194u8, 44u8, 196u8, 190u8, 74u8, 29u8, 0u8, 225u8, 245u8, 5u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8]; // Wrong public inputs
        
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
        let vk_bytes = vector[83u8, 4u8, 216u8, 252u8, 25u8, 246u8, 102u8, 57u8, 184u8, 218u8, 47u8, 146u8, 198u8, 124u8, 70u8, 97u8, 247u8, 161u8, 166u8, 179u8, 33u8, 105u8, 55u8, 21u8, 43u8, 139u8, 27u8, 182u8, 3u8, 87u8, 65u8, 132u8, 65u8, 155u8, 58u8, 20u8, 63u8, 176u8, 149u8, 16u8, 64u8, 71u8, 129u8, 78u8, 183u8, 204u8, 126u8, 161u8, 149u8, 25u8, 177u8, 98u8, 168u8, 40u8, 190u8, 35u8, 235u8, 183u8, 123u8, 138u8, 228u8, 178u8, 183u8, 19u8, 83u8, 29u8, 245u8, 1u8, 171u8, 165u8, 116u8, 114u8, 148u8, 120u8, 225u8, 251u8, 54u8, 51u8, 17u8, 202u8, 60u8, 110u8, 255u8, 41u8, 104u8, 215u8, 176u8, 59u8, 160u8, 0u8, 110u8, 156u8, 97u8, 164u8, 2u8, 27u8, 252u8, 73u8, 114u8, 153u8, 90u8, 120u8, 120u8, 87u8, 173u8, 100u8, 211u8, 255u8, 254u8, 49u8, 163u8, 47u8, 179u8, 247u8, 42u8, 206u8, 44u8, 48u8, 129u8, 97u8, 99u8, 235u8, 133u8, 54u8, 205u8, 3u8, 76u8, 37u8, 30u8, 107u8, 2u8, 164u8, 66u8, 66u8, 122u8, 116u8, 235u8, 243u8, 59u8, 130u8, 173u8, 179u8, 45u8, 71u8, 119u8, 81u8, 220u8, 98u8, 205u8, 241u8, 3u8, 37u8, 201u8, 199u8, 202u8, 241u8, 89u8, 233u8, 107u8, 41u8, 210u8, 147u8, 255u8, 135u8, 35u8, 119u8, 205u8, 112u8, 213u8, 40u8, 220u8, 255u8, 24u8, 133u8, 115u8, 161u8, 207u8, 235u8, 224u8, 159u8, 98u8, 102u8, 44u8, 53u8, 247u8, 15u8, 72u8, 29u8, 2u8, 157u8, 16u8, 19u8, 78u8, 90u8, 139u8, 89u8, 87u8, 203u8, 27u8, 0u8, 244u8, 62u8, 38u8, 8u8, 243u8, 217u8, 238u8, 13u8, 31u8, 164u8, 224u8, 44u8, 217u8, 123u8, 241u8, 91u8, 226u8, 152u8, 83u8, 80u8, 94u8, 192u8, 162u8, 6u8, 3u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 6u8, 3u8, 21u8, 166u8, 215u8, 205u8, 158u8, 88u8, 135u8, 22u8, 228u8, 191u8, 44u8, 64u8, 254u8, 160u8, 19u8, 66u8, 197u8, 1u8, 170u8, 36u8, 172u8, 45u8, 45u8, 143u8, 115u8, 108u8, 77u8, 236u8, 251u8, 9u8, 151u8, 91u8, 97u8, 96u8, 36u8, 38u8, 26u8, 133u8, 103u8, 109u8, 44u8, 169u8, 143u8, 108u8, 61u8, 64u8, 167u8, 136u8, 107u8, 191u8, 224u8, 153u8, 248u8, 204u8, 92u8, 130u8, 138u8, 47u8, 16u8, 141u8, 62u8, 171u8, 20u8, 134u8, 73u8, 133u8, 59u8, 24u8, 123u8, 248u8, 156u8, 219u8, 48u8, 152u8, 190u8, 72u8, 245u8, 90u8, 117u8, 5u8, 234u8, 116u8, 174u8, 64u8, 108u8, 37u8, 49u8, 14u8, 98u8, 123u8, 217u8, 162u8, 27u8, 163u8];
        
        let ctx = test_scenario::ctx(&mut scenario);
        proximity::init_verifying_key(&server_cap, vk_bytes, ctx);
        
        test_scenario::return_to_sender(&scenario, server_cap);
    };

    // Create commitment with different coordinates
    scenario.next_tx(@0x1);
    {
        let server_cap = test_scenario::take_from_sender<proximity::ServerCap>(&scenario);
        let commitment_bytes = vector[112u8, 143u8, 93u8, 237u8, 28u8, 16u8, 233u8, 200u8, 152u8, 35u8, 156u8, 32u8, 175u8, 255u8, 46u8, 200u8, 2u8, 145u8, 247u8, 229u8, 59u8, 33u8, 251u8, 111u8, 5u8, 240u8, 127u8, 120u8, 67u8, 138u8, 125u8, 32u8]; // Different Poseidon commitment hash (32 bytes)
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
        let proof_bytes = vector[174u8, 56u8, 75u8, 26u8, 197u8, 12u8, 216u8, 140u8, 169u8, 55u8, 173u8, 173u8, 167u8, 55u8, 12u8, 41u8, 89u8, 206u8, 223u8, 112u8, 106u8, 64u8, 9u8, 173u8, 230u8, 225u8, 63u8, 218u8, 86u8, 139u8, 249u8, 161u8, 91u8, 4u8, 15u8, 132u8, 34u8, 167u8, 165u8, 22u8, 119u8, 7u8, 36u8, 0u8, 251u8, 229u8, 81u8, 228u8, 222u8, 18u8, 248u8, 176u8, 175u8, 211u8, 216u8, 3u8, 252u8, 165u8, 82u8, 170u8, 8u8, 27u8, 207u8, 28u8, 41u8, 251u8, 128u8, 44u8, 225u8, 180u8, 93u8, 197u8, 32u8, 250u8, 34u8, 244u8, 73u8, 222u8, 220u8, 194u8, 130u8, 52u8, 23u8, 59u8, 49u8, 86u8, 57u8, 120u8, 107u8, 23u8, 11u8, 252u8, 94u8, 170u8, 168u8, 131u8, 31u8, 112u8, 171u8, 175u8, 237u8, 183u8, 94u8, 244u8, 186u8, 60u8, 118u8, 161u8, 70u8, 96u8, 206u8, 30u8, 197u8, 190u8, 74u8, 232u8, 145u8, 161u8, 98u8, 228u8, 240u8, 234u8, 7u8, 188u8, 98u8, 164u8, 116u8, 168u8];
        let public_inputs = vector[112u8, 143u8, 93u8, 237u8, 28u8, 16u8, 233u8, 200u8, 152u8, 35u8, 156u8, 32u8, 175u8, 255u8, 46u8, 200u8, 2u8, 145u8, 247u8, 229u8, 59u8, 33u8, 251u8, 111u8, 5u8, 240u8, 127u8, 120u8, 67u8, 138u8, 125u8, 32u8, 0u8, 225u8, 245u8, 5u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8];
        
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
        let vk_bytes = vector[83u8, 4u8, 216u8, 252u8, 25u8, 246u8, 102u8, 57u8, 184u8, 218u8, 47u8, 146u8, 198u8, 124u8, 70u8, 97u8, 247u8, 161u8, 166u8, 179u8, 33u8, 105u8, 55u8, 21u8, 43u8, 139u8, 27u8, 182u8, 3u8, 87u8, 65u8, 132u8, 65u8, 155u8, 58u8, 20u8, 63u8, 176u8, 149u8, 16u8, 64u8, 71u8, 129u8, 78u8, 183u8, 204u8, 126u8, 161u8, 149u8, 25u8, 177u8, 98u8, 168u8, 40u8, 190u8, 35u8, 235u8, 183u8, 123u8, 138u8, 228u8, 178u8, 183u8, 19u8, 83u8, 29u8, 245u8, 1u8, 171u8, 165u8, 116u8, 114u8, 148u8, 120u8, 225u8, 251u8, 54u8, 51u8, 17u8, 202u8, 60u8, 110u8, 255u8, 41u8, 104u8, 215u8, 176u8, 59u8, 160u8, 0u8, 110u8, 156u8, 97u8, 164u8, 2u8, 27u8, 252u8, 73u8, 114u8, 153u8, 90u8, 120u8, 120u8, 87u8, 173u8, 100u8, 211u8, 255u8, 254u8, 49u8, 163u8, 47u8, 179u8, 247u8, 42u8, 206u8, 44u8, 48u8, 129u8, 97u8, 99u8, 235u8, 133u8, 54u8, 205u8, 3u8, 76u8, 37u8, 30u8, 107u8, 2u8, 164u8, 66u8, 66u8, 122u8, 116u8, 235u8, 243u8, 59u8, 130u8, 173u8, 179u8, 45u8, 71u8, 119u8, 81u8, 220u8, 98u8, 205u8, 241u8, 3u8, 37u8, 201u8, 199u8, 202u8, 241u8, 89u8, 233u8, 107u8, 41u8, 210u8, 147u8, 255u8, 135u8, 35u8, 119u8, 205u8, 112u8, 213u8, 40u8, 220u8, 255u8, 24u8, 133u8, 115u8, 161u8, 207u8, 235u8, 224u8, 159u8, 98u8, 102u8, 44u8, 53u8, 247u8, 15u8, 72u8, 29u8, 2u8, 157u8, 16u8, 19u8, 78u8, 90u8, 139u8, 89u8, 87u8, 203u8, 27u8, 0u8, 244u8, 62u8, 38u8, 8u8, 243u8, 217u8, 238u8, 13u8, 31u8, 164u8, 224u8, 44u8, 217u8, 123u8, 241u8, 91u8, 226u8, 152u8, 83u8, 80u8, 94u8, 192u8, 162u8, 6u8, 3u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 6u8, 3u8, 21u8, 166u8, 215u8, 205u8, 158u8, 88u8, 135u8, 22u8, 228u8, 191u8, 44u8, 64u8, 254u8, 160u8, 19u8, 66u8, 197u8, 1u8, 170u8, 36u8, 172u8, 45u8, 45u8, 143u8, 115u8, 108u8, 77u8, 236u8, 251u8, 9u8, 151u8, 91u8, 97u8, 96u8, 36u8, 38u8, 26u8, 133u8, 103u8, 109u8, 44u8, 169u8, 143u8, 108u8, 61u8, 64u8, 167u8, 136u8, 107u8, 191u8, 224u8, 153u8, 248u8, 204u8, 92u8, 130u8, 138u8, 47u8, 16u8, 141u8, 62u8, 171u8, 20u8, 134u8, 73u8, 133u8, 59u8, 24u8, 123u8, 248u8, 156u8, 219u8, 48u8, 152u8, 190u8, 72u8, 245u8, 90u8, 117u8, 5u8, 234u8, 116u8, 174u8, 64u8, 108u8, 37u8, 49u8, 14u8, 98u8, 123u8, 217u8, 162u8, 27u8, 163u8];
        
        let ctx = test_scenario::ctx(&mut scenario);
        proximity::init_verifying_key(&server_cap, vk_bytes, ctx);
        
        test_scenario::return_to_sender(&scenario, server_cap);
    };

    // Create commitment with absolute value coordinates
    scenario.next_tx(@0x1);
    {
        let server_cap = test_scenario::take_from_sender<proximity::ServerCap>(&scenario);
        let commitment_bytes = vector[132u8, 186u8, 167u8, 168u8, 132u8, 246u8, 238u8, 189u8, 66u8, 74u8, 132u8, 179u8, 89u8, 17u8, 131u8, 221u8, 169u8, 74u8, 7u8, 31u8, 181u8, 8u8, 226u8, 91u8, 19u8, 212u8, 89u8, 119u8, 137u8, 85u8, 88u8, 7u8]; // Absolute value Poseidon commitment hash (32 bytes)
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
        let proof_bytes = vector[98u8, 83u8, 68u8, 181u8, 54u8, 124u8, 6u8, 188u8, 121u8, 253u8, 92u8, 83u8, 89u8, 55u8, 4u8, 162u8, 79u8, 197u8, 97u8, 42u8, 66u8, 229u8, 101u8, 64u8, 81u8, 118u8, 44u8, 43u8, 141u8, 246u8, 110u8, 46u8, 185u8, 39u8, 200u8, 130u8, 178u8, 75u8, 40u8, 143u8, 8u8, 63u8, 121u8, 245u8, 145u8, 92u8, 208u8, 131u8, 220u8, 121u8, 251u8, 242u8, 198u8, 178u8, 61u8, 230u8, 198u8, 89u8, 240u8, 164u8, 248u8, 159u8, 205u8, 5u8, 172u8, 102u8, 34u8, 127u8, 126u8, 185u8, 142u8, 94u8, 108u8, 48u8, 62u8, 200u8, 158u8, 54u8, 144u8, 8u8, 27u8, 146u8, 121u8, 154u8, 118u8, 82u8, 90u8, 192u8, 237u8, 30u8, 164u8, 30u8, 52u8, 221u8, 244u8, 17u8, 118u8, 126u8, 30u8, 76u8, 145u8, 217u8, 204u8, 197u8, 41u8, 221u8, 176u8, 60u8, 80u8, 62u8, 47u8, 117u8, 3u8, 158u8, 67u8, 135u8, 4u8, 113u8, 112u8, 135u8, 178u8, 13u8, 7u8, 231u8, 168u8, 170u8, 83u8, 138u8];
        let public_inputs = vector[242u8, 103u8, 23u8, 88u8, 12u8, 96u8, 149u8, 7u8, 157u8, 65u8, 33u8, 229u8, 8u8, 31u8, 71u8, 135u8, 53u8, 164u8, 180u8, 172u8, 145u8, 46u8, 85u8, 54u8, 26u8, 90u8, 194u8, 44u8, 196u8, 190u8, 74u8, 29u8, 0u8, 225u8, 245u8, 5u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8];
        
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
        let vk_bytes = vector[83u8, 4u8, 216u8, 252u8, 25u8, 246u8, 102u8, 57u8, 184u8, 218u8, 47u8, 146u8, 198u8, 124u8, 70u8, 97u8, 247u8, 161u8, 166u8, 179u8, 33u8, 105u8, 55u8, 21u8, 43u8, 139u8, 27u8, 182u8, 3u8, 87u8, 65u8, 132u8, 65u8, 155u8, 58u8, 20u8, 63u8, 176u8, 149u8, 16u8, 64u8, 71u8, 129u8, 78u8, 183u8, 204u8, 126u8, 161u8, 149u8, 25u8, 177u8, 98u8, 168u8, 40u8, 190u8, 35u8, 235u8, 183u8, 123u8, 138u8, 228u8, 178u8, 183u8, 19u8, 83u8, 29u8, 245u8, 1u8, 171u8, 165u8, 116u8, 114u8, 148u8, 120u8, 225u8, 251u8, 54u8, 51u8, 17u8, 202u8, 60u8, 110u8, 255u8, 41u8, 104u8, 215u8, 176u8, 59u8, 160u8, 0u8, 110u8, 156u8, 97u8, 164u8, 2u8, 27u8, 252u8, 73u8, 114u8, 153u8, 90u8, 120u8, 120u8, 87u8, 173u8, 100u8, 211u8, 255u8, 254u8, 49u8, 163u8, 47u8, 179u8, 247u8, 42u8, 206u8, 44u8, 48u8, 129u8, 97u8, 99u8, 235u8, 133u8, 54u8, 205u8, 3u8, 76u8, 37u8, 30u8, 107u8, 2u8, 164u8, 66u8, 66u8, 122u8, 116u8, 235u8, 243u8, 59u8, 130u8, 173u8, 179u8, 45u8, 71u8, 119u8, 81u8, 220u8, 98u8, 205u8, 241u8, 3u8, 37u8, 201u8, 199u8, 202u8, 241u8, 89u8, 233u8, 107u8, 41u8, 210u8, 147u8, 255u8, 135u8, 35u8, 119u8, 205u8, 112u8, 213u8, 40u8, 220u8, 255u8, 24u8, 133u8, 115u8, 161u8, 207u8, 235u8, 224u8, 159u8, 98u8, 102u8, 44u8, 53u8, 247u8, 15u8, 72u8, 29u8, 2u8, 157u8, 16u8, 19u8, 78u8, 90u8, 139u8, 89u8, 87u8, 203u8, 27u8, 0u8, 244u8, 62u8, 38u8, 8u8, 243u8, 217u8, 238u8, 13u8, 31u8, 164u8, 224u8, 44u8, 217u8, 123u8, 241u8, 91u8, 226u8, 152u8, 83u8, 80u8, 94u8, 192u8, 162u8, 6u8, 3u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 6u8, 3u8, 21u8, 166u8, 215u8, 205u8, 158u8, 88u8, 135u8, 22u8, 228u8, 191u8, 44u8, 64u8, 254u8, 160u8, 19u8, 66u8, 197u8, 1u8, 170u8, 36u8, 172u8, 45u8, 45u8, 143u8, 115u8, 108u8, 77u8, 236u8, 251u8, 9u8, 151u8, 91u8, 97u8, 96u8, 36u8, 38u8, 26u8, 133u8, 103u8, 109u8, 44u8, 169u8, 143u8, 108u8, 61u8, 64u8, 167u8, 136u8, 107u8, 191u8, 224u8, 153u8, 248u8, 204u8, 92u8, 130u8, 138u8, 47u8, 16u8, 141u8, 62u8, 171u8, 20u8, 134u8, 73u8, 133u8, 59u8, 24u8, 123u8, 248u8, 156u8, 219u8, 48u8, 152u8, 190u8, 72u8, 245u8, 90u8, 117u8, 5u8, 234u8, 116u8, 174u8, 64u8, 108u8, 37u8, 49u8, 14u8, 98u8, 123u8, 217u8, 162u8, 27u8, 163u8];
        
        let ctx = test_scenario::ctx(&mut scenario);
        proximity::init_verifying_key(&server_cap, vk_bytes, ctx);
        
        test_scenario::return_to_sender(&scenario, server_cap);
    };

    // Create commitment with SSU_B hash
    scenario.next_tx(@0x1);
    {
        let server_cap = test_scenario::take_from_sender<proximity::ServerCap>(&scenario);
        let commitment_b_bytes = vector[112u8, 143u8, 93u8, 237u8, 28u8, 16u8, 233u8, 200u8, 152u8, 35u8, 156u8, 32u8, 175u8, 255u8, 46u8, 200u8, 2u8, 145u8, 247u8, 229u8, 59u8, 33u8, 251u8, 111u8, 5u8, 240u8, 127u8, 120u8, 67u8, 138u8, 125u8, 32u8]; // SSU_B commitment hash
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
        
        let proof_for_ssu_a = vector[98u8, 83u8, 68u8, 181u8, 54u8, 124u8, 6u8, 188u8, 121u8, 253u8, 92u8, 83u8, 89u8, 55u8, 4u8, 162u8, 79u8, 197u8, 97u8, 42u8, 66u8, 229u8, 101u8, 64u8, 81u8, 118u8, 44u8, 43u8, 141u8, 246u8, 110u8, 46u8, 185u8, 39u8, 200u8, 130u8, 178u8, 75u8, 40u8, 143u8, 8u8, 63u8, 121u8, 245u8, 145u8, 92u8, 208u8, 131u8, 220u8, 121u8, 251u8, 242u8, 198u8, 178u8, 61u8, 230u8, 198u8, 89u8, 240u8, 164u8, 248u8, 159u8, 205u8, 5u8, 172u8, 102u8, 34u8, 127u8, 126u8, 185u8, 142u8, 94u8, 108u8, 48u8, 62u8, 200u8, 158u8, 54u8, 144u8, 8u8, 27u8, 146u8, 121u8, 154u8, 118u8, 82u8, 90u8, 192u8, 237u8, 30u8, 164u8, 30u8, 52u8, 221u8, 244u8, 17u8, 118u8, 126u8, 30u8, 76u8, 145u8, 217u8, 204u8, 197u8, 41u8, 221u8, 176u8, 60u8, 80u8, 62u8, 47u8, 117u8, 3u8, 158u8, 67u8, 135u8, 4u8, 113u8, 112u8, 135u8, 178u8, 13u8, 7u8, 231u8, 168u8, 170u8, 83u8, 138u8]; // Valid proof for SSU_A
        let public_inputs_for_ssu_a = vector[242u8, 103u8, 23u8, 88u8, 12u8, 96u8, 149u8, 7u8, 157u8, 65u8, 33u8, 229u8, 8u8, 31u8, 71u8, 135u8, 53u8, 164u8, 180u8, 172u8, 145u8, 46u8, 85u8, 54u8, 26u8, 90u8, 194u8, 44u8, 196u8, 190u8, 74u8, 29u8, 0u8, 225u8, 245u8, 5u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8]; // Public inputs containing SSU_A's hash (WRONG!)
        
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
        let vk_bytes = vector[83u8, 4u8, 216u8, 252u8, 25u8, 246u8, 102u8, 57u8, 184u8, 218u8, 47u8, 146u8, 198u8, 124u8, 70u8, 97u8, 247u8, 161u8, 166u8, 179u8, 33u8, 105u8, 55u8, 21u8, 43u8, 139u8, 27u8, 182u8, 3u8, 87u8, 65u8, 132u8, 65u8, 155u8, 58u8, 20u8, 63u8, 176u8, 149u8, 16u8, 64u8, 71u8, 129u8, 78u8, 183u8, 204u8, 126u8, 161u8, 149u8, 25u8, 177u8, 98u8, 168u8, 40u8, 190u8, 35u8, 235u8, 183u8, 123u8, 138u8, 228u8, 178u8, 183u8, 19u8, 83u8, 29u8, 245u8, 1u8, 171u8, 165u8, 116u8, 114u8, 148u8, 120u8, 225u8, 251u8, 54u8, 51u8, 17u8, 202u8, 60u8, 110u8, 255u8, 41u8, 104u8, 215u8, 176u8, 59u8, 160u8, 0u8, 110u8, 156u8, 97u8, 164u8, 2u8, 27u8, 252u8, 73u8, 114u8, 153u8, 90u8, 120u8, 120u8, 87u8, 173u8, 100u8, 211u8, 255u8, 254u8, 49u8, 163u8, 47u8, 179u8, 247u8, 42u8, 206u8, 44u8, 48u8, 129u8, 97u8, 99u8, 235u8, 133u8, 54u8, 205u8, 3u8, 76u8, 37u8, 30u8, 107u8, 2u8, 164u8, 66u8, 66u8, 122u8, 116u8, 235u8, 243u8, 59u8, 130u8, 173u8, 179u8, 45u8, 71u8, 119u8, 81u8, 220u8, 98u8, 205u8, 241u8, 3u8, 37u8, 201u8, 199u8, 202u8, 241u8, 89u8, 233u8, 107u8, 41u8, 210u8, 147u8, 255u8, 135u8, 35u8, 119u8, 205u8, 112u8, 213u8, 40u8, 220u8, 255u8, 24u8, 133u8, 115u8, 161u8, 207u8, 235u8, 224u8, 159u8, 98u8, 102u8, 44u8, 53u8, 247u8, 15u8, 72u8, 29u8, 2u8, 157u8, 16u8, 19u8, 78u8, 90u8, 139u8, 89u8, 87u8, 203u8, 27u8, 0u8, 244u8, 62u8, 38u8, 8u8, 243u8, 217u8, 238u8, 13u8, 31u8, 164u8, 224u8, 44u8, 217u8, 123u8, 241u8, 91u8, 226u8, 152u8, 83u8, 80u8, 94u8, 192u8, 162u8, 6u8, 3u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 6u8, 3u8, 21u8, 166u8, 215u8, 205u8, 158u8, 88u8, 135u8, 22u8, 228u8, 191u8, 44u8, 64u8, 254u8, 160u8, 19u8, 66u8, 197u8, 1u8, 170u8, 36u8, 172u8, 45u8, 45u8, 143u8, 115u8, 108u8, 77u8, 236u8, 251u8, 9u8, 151u8, 91u8, 97u8, 96u8, 36u8, 38u8, 26u8, 133u8, 103u8, 109u8, 44u8, 169u8, 143u8, 108u8, 61u8, 64u8, 167u8, 136u8, 107u8, 191u8, 224u8, 153u8, 248u8, 204u8, 92u8, 130u8, 138u8, 47u8, 16u8, 141u8, 62u8, 171u8, 20u8, 134u8, 73u8, 133u8, 59u8, 24u8, 123u8, 248u8, 156u8, 219u8, 48u8, 152u8, 190u8, 72u8, 245u8, 90u8, 117u8, 5u8, 234u8, 116u8, 174u8, 64u8, 108u8, 37u8, 49u8, 14u8, 98u8, 123u8, 217u8, 162u8, 27u8, 163u8];
        
        let ctx = test_scenario::ctx(&mut scenario);
        proximity::init_verifying_key(&server_cap, vk_bytes, ctx);
        
        test_scenario::return_to_sender(&scenario, server_cap);
    };

    // Create commitment with SSU_A hash
    scenario.next_tx(@0x1);
    {
        let server_cap = test_scenario::take_from_sender<proximity::ServerCap>(&scenario);
        let commitment_bytes = vector[242u8, 103u8, 23u8, 88u8, 12u8, 96u8, 149u8, 7u8, 157u8, 65u8, 33u8, 229u8, 8u8, 31u8, 71u8, 135u8, 53u8, 164u8, 180u8, 172u8, 145u8, 46u8, 85u8, 54u8, 26u8, 90u8, 194u8, 44u8, 196u8, 190u8, 74u8, 29u8]; // SSU_A commitment hash
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
        let proof_bytes = vector[98u8, 83u8, 68u8, 181u8, 54u8, 124u8, 6u8, 188u8, 121u8, 253u8, 92u8, 83u8, 89u8, 55u8, 4u8, 162u8, 79u8, 197u8, 97u8, 42u8, 66u8, 229u8, 101u8, 64u8, 81u8, 118u8, 44u8, 43u8, 141u8, 246u8, 110u8, 46u8, 185u8, 39u8, 200u8, 130u8, 178u8, 75u8, 40u8, 143u8, 8u8, 63u8, 121u8, 245u8, 145u8, 92u8, 208u8, 131u8, 220u8, 121u8, 251u8, 242u8, 198u8, 178u8, 61u8, 230u8, 198u8, 89u8, 240u8, 164u8, 248u8, 159u8, 205u8, 5u8, 172u8, 102u8, 34u8, 127u8, 126u8, 185u8, 142u8, 94u8, 108u8, 48u8, 62u8, 200u8, 158u8, 54u8, 144u8, 8u8, 27u8, 146u8, 121u8, 154u8, 118u8, 82u8, 90u8, 192u8, 237u8, 30u8, 164u8, 30u8, 52u8, 221u8, 244u8, 17u8, 118u8, 126u8, 30u8, 76u8, 145u8, 217u8, 204u8, 197u8, 41u8, 221u8, 176u8, 60u8, 80u8, 62u8, 47u8, 117u8, 3u8, 158u8, 67u8, 135u8, 4u8, 113u8, 112u8, 135u8, 178u8, 13u8, 7u8, 231u8, 168u8, 170u8, 83u8, 138u8]; // Valid proof for SSU_A
        let public_inputs = vector[242u8, 103u8, 23u8, 88u8, 12u8, 96u8, 149u8, 7u8, 157u8, 65u8, 33u8, 229u8, 8u8, 31u8, 71u8, 135u8, 53u8, 164u8, 180u8, 172u8, 145u8, 46u8, 85u8, 54u8, 26u8, 90u8, 194u8, 44u8, 196u8, 190u8, 74u8, 29u8, 0u8, 225u8, 245u8, 5u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8]; // Public inputs with SSU_A hash (CORRECT!)
        
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
