
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
        let vk_bytes = vector[23u8, 138u8, 155u8, 211u8, 67u8, 147u8, 133u8, 109u8, 1u8, 62u8, 99u8, 159u8, 233u8, 140u8, 53u8, 36u8, 14u8, 4u8, 128u8, 106u8, 179u8, 107u8, 187u8, 219u8, 16u8, 225u8, 10u8, 148u8, 192u8, 15u8, 51u8, 161u8, 116u8, 39u8, 237u8, 32u8, 178u8, 228u8, 151u8, 22u8, 220u8, 200u8, 125u8, 69u8, 131u8, 8u8, 12u8, 206u8, 0u8, 229u8, 227u8, 178u8, 170u8, 243u8, 186u8, 163u8, 128u8, 210u8, 153u8, 102u8, 26u8, 82u8, 24u8, 43u8, 228u8, 232u8, 104u8, 21u8, 142u8, 99u8, 80u8, 144u8, 104u8, 28u8, 42u8, 24u8, 253u8, 30u8, 110u8, 52u8, 131u8, 130u8, 218u8, 255u8, 22u8, 110u8, 126u8, 135u8, 31u8, 142u8, 137u8, 112u8, 48u8, 64u8, 130u8, 139u8, 167u8, 246u8, 154u8, 3u8, 252u8, 255u8, 123u8, 74u8, 180u8, 45u8, 127u8, 71u8, 157u8, 141u8, 139u8, 153u8, 23u8, 105u8, 248u8, 231u8, 69u8, 210u8, 65u8, 245u8, 198u8, 19u8, 140u8, 120u8, 203u8, 137u8, 172u8, 30u8, 44u8, 47u8, 21u8, 225u8, 140u8, 0u8, 35u8, 141u8, 46u8, 248u8, 226u8, 176u8, 3u8, 145u8, 194u8, 179u8, 232u8, 110u8, 106u8, 190u8, 41u8, 115u8, 238u8, 7u8, 161u8, 236u8, 57u8, 168u8, 125u8, 87u8, 88u8, 22u8, 30u8, 217u8, 109u8, 167u8, 66u8, 193u8, 105u8, 111u8, 39u8, 10u8, 165u8, 80u8, 161u8, 136u8, 100u8, 89u8, 214u8, 46u8, 126u8, 37u8, 86u8, 44u8, 58u8, 90u8, 165u8, 155u8, 161u8, 68u8, 182u8, 226u8, 163u8, 11u8, 7u8, 217u8, 83u8, 68u8, 6u8, 143u8, 144u8, 203u8, 180u8, 235u8, 140u8, 97u8, 163u8, 127u8, 96u8, 158u8, 236u8, 129u8, 177u8, 12u8, 77u8, 215u8, 231u8, 120u8, 222u8, 52u8, 248u8, 219u8, 135u8, 48u8, 142u8, 160u8, 3u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 92u8, 25u8, 107u8, 232u8, 25u8, 59u8, 145u8, 147u8, 242u8, 158u8, 220u8, 97u8, 213u8, 52u8, 175u8, 25u8, 232u8, 239u8, 70u8, 198u8, 208u8, 191u8, 240u8, 53u8, 211u8, 37u8, 92u8, 64u8, 153u8, 138u8, 46u8, 28u8, 47u8, 243u8, 185u8, 85u8, 218u8, 94u8, 77u8, 101u8, 75u8, 18u8, 73u8, 116u8, 64u8, 53u8, 57u8, 1u8, 45u8, 130u8, 114u8, 43u8, 13u8, 125u8, 209u8, 130u8, 211u8, 103u8, 214u8, 40u8, 181u8, 89u8, 126u8, 47u8, 14u8, 239u8, 104u8, 49u8, 131u8, 89u8, 2u8, 122u8, 1u8, 32u8, 47u8, 202u8, 203u8, 135u8, 49u8, 140u8, 158u8, 21u8, 223u8, 138u8, 189u8, 81u8, 177u8, 73u8, 219u8, 60u8, 237u8, 23u8, 116u8, 89u8, 102u8, 34u8]; // Canonical verifying key (328 bytes)
        
        let ctx = test_scenario::ctx(&mut scenario);
        proximity::init_verifying_key(&server_cap, vk_bytes, ctx);
        
        test_scenario::return_to_sender(&scenario, server_cap);
    };

    // Create commitment (Poseidon hash - 32 bytes)
    scenario.next_tx(@0x1);
    {
        let server_cap = test_scenario::take_from_sender<proximity::ServerCap>(&scenario);
        let commitment_bytes = vector[248u8, 131u8, 40u8, 89u8, 23u8, 32u8, 57u8, 7u8, 52u8, 90u8, 245u8, 13u8, 132u8, 70u8, 39u8, 31u8, 172u8, 39u8, 109u8, 47u8, 128u8, 57u8, 248u8, 189u8, 14u8, 208u8, 38u8, 64u8, 230u8, 48u8, 88u8, 31u8]; // Poseidon hash (32 bytes)
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
        let proof_bytes = vector[131u8, 95u8, 56u8, 63u8, 237u8, 79u8, 97u8, 21u8, 26u8, 232u8, 246u8, 184u8, 120u8, 193u8, 222u8, 2u8, 115u8, 72u8, 223u8, 181u8, 130u8, 192u8, 126u8, 186u8, 84u8, 94u8, 156u8, 160u8, 231u8, 225u8, 240u8, 23u8, 163u8, 27u8, 230u8, 76u8, 15u8, 225u8, 72u8, 15u8, 201u8, 80u8, 140u8, 19u8, 6u8, 22u8, 82u8, 96u8, 112u8, 107u8, 234u8, 224u8, 216u8, 140u8, 30u8, 255u8, 82u8, 151u8, 93u8, 227u8, 204u8, 51u8, 96u8, 8u8, 27u8, 79u8, 209u8, 58u8, 123u8, 233u8, 135u8, 112u8, 159u8, 221u8, 49u8, 34u8, 135u8, 174u8, 33u8, 57u8, 37u8, 252u8, 97u8, 193u8, 75u8, 218u8, 192u8, 12u8, 226u8, 17u8, 131u8, 37u8, 81u8, 182u8, 238u8, 148u8, 91u8, 112u8, 244u8, 106u8, 136u8, 27u8, 91u8, 133u8, 143u8, 208u8, 0u8, 26u8, 232u8, 92u8, 225u8, 30u8, 89u8, 181u8, 45u8, 5u8, 97u8, 207u8, 228u8, 235u8, 241u8, 195u8, 251u8, 221u8, 64u8, 58u8, 148u8, 10u8];
        let public_inputs = vector[248u8, 131u8, 40u8, 89u8, 23u8, 32u8, 57u8, 7u8, 52u8, 90u8, 245u8, 13u8, 132u8, 70u8, 39u8, 31u8, 172u8, 39u8, 109u8, 47u8, 128u8, 57u8, 248u8, 189u8, 14u8, 208u8, 38u8, 64u8, 230u8, 48u8, 88u8, 31u8, 0u8, 225u8, 245u8, 5u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8]; // [commitment_hash, max_distance_squared] (64 bytes total)
        
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
        let vk_bytes = vector[23u8, 138u8, 155u8, 211u8, 67u8, 147u8, 133u8, 109u8, 1u8, 62u8, 99u8, 159u8, 233u8, 140u8, 53u8, 36u8, 14u8, 4u8, 128u8, 106u8, 179u8, 107u8, 187u8, 219u8, 16u8, 225u8, 10u8, 148u8, 192u8, 15u8, 51u8, 161u8, 116u8, 39u8, 237u8, 32u8, 178u8, 228u8, 151u8, 22u8, 220u8, 200u8, 125u8, 69u8, 131u8, 8u8, 12u8, 206u8, 0u8, 229u8, 227u8, 178u8, 170u8, 243u8, 186u8, 163u8, 128u8, 210u8, 153u8, 102u8, 26u8, 82u8, 24u8, 43u8, 228u8, 232u8, 104u8, 21u8, 142u8, 99u8, 80u8, 144u8, 104u8, 28u8, 42u8, 24u8, 253u8, 30u8, 110u8, 52u8, 131u8, 130u8, 218u8, 255u8, 22u8, 110u8, 126u8, 135u8, 31u8, 142u8, 137u8, 112u8, 48u8, 64u8, 130u8, 139u8, 167u8, 246u8, 154u8, 3u8, 252u8, 255u8, 123u8, 74u8, 180u8, 45u8, 127u8, 71u8, 157u8, 141u8, 139u8, 153u8, 23u8, 105u8, 248u8, 231u8, 69u8, 210u8, 65u8, 245u8, 198u8, 19u8, 140u8, 120u8, 203u8, 137u8, 172u8, 30u8, 44u8, 47u8, 21u8, 225u8, 140u8, 0u8, 35u8, 141u8, 46u8, 248u8, 226u8, 176u8, 3u8, 145u8, 194u8, 179u8, 232u8, 110u8, 106u8, 190u8, 41u8, 115u8, 238u8, 7u8, 161u8, 236u8, 57u8, 168u8, 125u8, 87u8, 88u8, 22u8, 30u8, 217u8, 109u8, 167u8, 66u8, 193u8, 105u8, 111u8, 39u8, 10u8, 165u8, 80u8, 161u8, 136u8, 100u8, 89u8, 214u8, 46u8, 126u8, 37u8, 86u8, 44u8, 58u8, 90u8, 165u8, 155u8, 161u8, 68u8, 182u8, 226u8, 163u8, 11u8, 7u8, 217u8, 83u8, 68u8, 6u8, 143u8, 144u8, 203u8, 180u8, 235u8, 140u8, 97u8, 163u8, 127u8, 96u8, 158u8, 236u8, 129u8, 177u8, 12u8, 77u8, 215u8, 231u8, 120u8, 222u8, 52u8, 248u8, 219u8, 135u8, 48u8, 142u8, 160u8, 3u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 92u8, 25u8, 107u8, 232u8, 25u8, 59u8, 145u8, 147u8, 242u8, 158u8, 220u8, 97u8, 213u8, 52u8, 175u8, 25u8, 232u8, 239u8, 70u8, 198u8, 208u8, 191u8, 240u8, 53u8, 211u8, 37u8, 92u8, 64u8, 153u8, 138u8, 46u8, 28u8, 47u8, 243u8, 185u8, 85u8, 218u8, 94u8, 77u8, 101u8, 75u8, 18u8, 73u8, 116u8, 64u8, 53u8, 57u8, 1u8, 45u8, 130u8, 114u8, 43u8, 13u8, 125u8, 209u8, 130u8, 211u8, 103u8, 214u8, 40u8, 181u8, 89u8, 126u8, 47u8, 14u8, 239u8, 104u8, 49u8, 131u8, 89u8, 2u8, 122u8, 1u8, 32u8, 47u8, 202u8, 203u8, 135u8, 49u8, 140u8, 158u8, 21u8, 223u8, 138u8, 189u8, 81u8, 177u8, 73u8, 219u8, 60u8, 237u8, 23u8, 116u8, 89u8, 102u8, 34u8];
        
        let ctx = test_scenario::ctx(&mut scenario);
        proximity::init_verifying_key(&server_cap, vk_bytes, ctx);
        
        test_scenario::return_to_sender(&scenario, server_cap);
    };

    // Create commitment
    scenario.next_tx(@0x1);
    {
        let server_cap = test_scenario::take_from_sender<proximity::ServerCap>(&scenario);
        let commitment_bytes = vector[248u8, 131u8, 40u8, 89u8, 23u8, 32u8, 57u8, 7u8, 52u8, 90u8, 245u8, 13u8, 132u8, 70u8, 39u8, 31u8, 172u8, 39u8, 109u8, 47u8, 128u8, 57u8, 248u8, 189u8, 14u8, 208u8, 38u8, 64u8, 230u8, 48u8, 88u8, 31u8];
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
        let proof_bytes = vector[131u8, 95u8, 56u8, 63u8, 237u8, 79u8, 97u8, 21u8, 26u8, 232u8, 9u8, 184u8, 120u8, 193u8, 222u8, 2u8, 115u8, 72u8, 223u8, 181u8, 130u8, 192u8, 126u8, 186u8, 84u8, 94u8, 156u8, 160u8, 231u8, 225u8, 240u8, 23u8, 163u8, 27u8, 230u8, 76u8, 15u8, 225u8, 72u8, 15u8, 201u8, 80u8, 140u8, 19u8, 6u8, 22u8, 82u8, 96u8, 112u8, 107u8, 234u8, 224u8, 216u8, 140u8, 30u8, 255u8, 82u8, 151u8, 93u8, 227u8, 204u8, 51u8, 96u8, 8u8, 27u8, 79u8, 209u8, 58u8, 123u8, 233u8, 135u8, 112u8, 159u8, 221u8, 49u8, 34u8, 135u8, 174u8, 33u8, 57u8, 37u8, 252u8, 97u8, 193u8, 75u8, 218u8, 192u8, 12u8, 226u8, 17u8, 131u8, 37u8, 81u8, 182u8, 238u8, 148u8, 91u8, 112u8, 244u8, 106u8, 136u8, 27u8, 91u8, 133u8, 143u8, 208u8, 0u8, 26u8, 232u8, 92u8, 225u8, 30u8, 89u8, 181u8, 45u8, 5u8, 97u8, 207u8, 228u8, 235u8, 241u8, 195u8, 251u8, 221u8, 64u8, 58u8, 148u8, 10u8]; // Corrupted proof bytes
        let public_inputs = vector[248u8, 131u8, 40u8, 89u8, 23u8, 32u8, 57u8, 7u8, 52u8, 90u8, 245u8, 13u8, 132u8, 70u8, 39u8, 31u8, 172u8, 39u8, 109u8, 47u8, 128u8, 57u8, 248u8, 189u8, 14u8, 208u8, 38u8, 64u8, 230u8, 48u8, 88u8, 31u8, 0u8, 225u8, 245u8, 5u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8];
        
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
        let wrong_vk_bytes = vector[18u8, 178u8, 51u8, 204u8, 252u8, 82u8, 56u8, 9u8, 196u8, 123u8, 104u8, 3u8, 188u8, 191u8, 202u8, 207u8, 89u8, 174u8, 207u8, 189u8, 126u8, 140u8, 138u8, 206u8, 99u8, 121u8, 66u8, 245u8, 247u8, 40u8, 194u8, 167u8, 226u8, 49u8, 208u8, 140u8, 144u8, 164u8, 108u8, 91u8, 195u8, 86u8, 111u8, 130u8, 207u8, 38u8, 4u8, 35u8, 107u8, 206u8, 246u8, 194u8, 85u8, 248u8, 64u8, 33u8, 120u8, 25u8, 215u8, 215u8, 241u8, 181u8, 150u8, 40u8, 58u8, 215u8, 48u8, 224u8, 18u8, 241u8, 3u8, 252u8, 224u8, 208u8, 36u8, 195u8, 234u8, 122u8, 113u8, 84u8, 43u8, 255u8, 27u8, 169u8, 227u8, 241u8, 119u8, 187u8, 173u8, 24u8, 206u8, 77u8, 0u8, 76u8, 210u8, 134u8, 57u8, 82u8, 118u8, 192u8, 217u8, 126u8, 2u8, 13u8, 71u8, 124u8, 95u8, 218u8, 234u8, 25u8, 220u8, 177u8, 120u8, 212u8, 62u8, 180u8, 7u8, 15u8, 63u8, 20u8, 141u8, 85u8, 232u8, 190u8, 6u8, 245u8, 130u8, 14u8, 157u8, 193u8, 229u8, 56u8, 7u8, 193u8, 125u8, 105u8, 66u8, 45u8, 104u8, 249u8, 47u8, 83u8, 218u8, 234u8, 198u8, 143u8, 124u8, 33u8, 90u8, 104u8, 200u8, 0u8, 157u8, 48u8, 213u8, 56u8, 80u8, 67u8, 152u8, 131u8, 77u8, 112u8, 168u8, 47u8, 164u8, 96u8, 61u8, 145u8, 83u8, 253u8, 71u8, 55u8, 129u8, 255u8, 235u8, 194u8, 125u8, 221u8, 167u8, 21u8, 31u8, 205u8, 137u8, 9u8, 169u8, 102u8, 139u8, 14u8, 129u8, 76u8, 99u8, 0u8, 108u8, 149u8, 155u8, 63u8, 52u8, 95u8, 180u8, 75u8, 92u8, 31u8, 5u8, 45u8, 193u8, 49u8, 122u8, 37u8, 21u8, 190u8, 1u8, 114u8, 75u8, 200u8, 95u8, 237u8, 12u8, 137u8, 65u8, 187u8, 179u8, 181u8, 21u8, 37u8, 3u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 175u8, 224u8, 212u8, 168u8, 35u8, 19u8, 62u8, 165u8, 194u8, 137u8, 228u8, 72u8, 76u8, 126u8, 227u8, 168u8, 61u8, 206u8, 116u8, 196u8, 65u8, 204u8, 144u8, 26u8, 98u8, 95u8, 143u8, 38u8, 193u8, 191u8, 44u8, 141u8, 69u8, 179u8, 242u8, 33u8, 180u8, 7u8, 22u8, 83u8, 172u8, 52u8, 151u8, 9u8, 153u8, 87u8, 141u8, 49u8, 100u8, 112u8, 84u8, 64u8, 5u8, 201u8, 164u8, 129u8, 54u8, 134u8, 163u8, 70u8, 49u8, 58u8, 252u8, 26u8, 191u8, 40u8, 5u8, 3u8, 27u8, 93u8, 195u8, 97u8, 178u8, 198u8, 219u8, 230u8, 227u8, 18u8, 44u8, 14u8, 204u8, 200u8, 15u8, 237u8, 51u8, 59u8, 223u8, 99u8, 77u8, 56u8, 221u8, 215u8, 249u8, 101u8, 114u8, 4u8]; // Wrong VK bytes (from different trusted setup)
        
        let ctx = test_scenario::ctx(&mut scenario);
        proximity::init_verifying_key(&server_cap, wrong_vk_bytes, ctx);
        
        test_scenario::return_to_sender(&scenario, server_cap);
    };

    // Create commitment
    scenario.next_tx(@0x1);
    {
        let server_cap = test_scenario::take_from_sender<proximity::ServerCap>(&scenario);
        let commitment_bytes = vector[248u8, 131u8, 40u8, 89u8, 23u8, 32u8, 57u8, 7u8, 52u8, 90u8, 245u8, 13u8, 132u8, 70u8, 39u8, 31u8, 172u8, 39u8, 109u8, 47u8, 128u8, 57u8, 248u8, 189u8, 14u8, 208u8, 38u8, 64u8, 230u8, 48u8, 88u8, 31u8];
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
        let proof_bytes = vector[131u8, 95u8, 56u8, 63u8, 237u8, 79u8, 97u8, 21u8, 26u8, 232u8, 246u8, 184u8, 120u8, 193u8, 222u8, 2u8, 115u8, 72u8, 223u8, 181u8, 130u8, 192u8, 126u8, 186u8, 84u8, 94u8, 156u8, 160u8, 231u8, 225u8, 240u8, 23u8, 163u8, 27u8, 230u8, 76u8, 15u8, 225u8, 72u8, 15u8, 201u8, 80u8, 140u8, 19u8, 6u8, 22u8, 82u8, 96u8, 112u8, 107u8, 234u8, 224u8, 216u8, 140u8, 30u8, 255u8, 82u8, 151u8, 93u8, 227u8, 204u8, 51u8, 96u8, 8u8, 27u8, 79u8, 209u8, 58u8, 123u8, 233u8, 135u8, 112u8, 159u8, 221u8, 49u8, 34u8, 135u8, 174u8, 33u8, 57u8, 37u8, 252u8, 97u8, 193u8, 75u8, 218u8, 192u8, 12u8, 226u8, 17u8, 131u8, 37u8, 81u8, 182u8, 238u8, 148u8, 91u8, 112u8, 244u8, 106u8, 136u8, 27u8, 91u8, 133u8, 143u8, 208u8, 0u8, 26u8, 232u8, 92u8, 225u8, 30u8, 89u8, 181u8, 45u8, 5u8, 97u8, 207u8, 228u8, 235u8, 241u8, 195u8, 251u8, 221u8, 64u8, 58u8, 148u8, 10u8]; // Proof generated with correct VK
        let public_inputs = vector[248u8, 131u8, 40u8, 89u8, 23u8, 32u8, 57u8, 7u8, 52u8, 90u8, 245u8, 13u8, 132u8, 70u8, 39u8, 31u8, 172u8, 39u8, 109u8, 47u8, 128u8, 57u8, 248u8, 189u8, 14u8, 208u8, 38u8, 64u8, 230u8, 48u8, 88u8, 31u8, 0u8, 225u8, 245u8, 5u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8];
        
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
        let vk_bytes = vector[23u8, 138u8, 155u8, 211u8, 67u8, 147u8, 133u8, 109u8, 1u8, 62u8, 99u8, 159u8, 233u8, 140u8, 53u8, 36u8, 14u8, 4u8, 128u8, 106u8, 179u8, 107u8, 187u8, 219u8, 16u8, 225u8, 10u8, 148u8, 192u8, 15u8, 51u8, 161u8, 116u8, 39u8, 237u8, 32u8, 178u8, 228u8, 151u8, 22u8, 220u8, 200u8, 125u8, 69u8, 131u8, 8u8, 12u8, 206u8, 0u8, 229u8, 227u8, 178u8, 170u8, 243u8, 186u8, 163u8, 128u8, 210u8, 153u8, 102u8, 26u8, 82u8, 24u8, 43u8, 228u8, 232u8, 104u8, 21u8, 142u8, 99u8, 80u8, 144u8, 104u8, 28u8, 42u8, 24u8, 253u8, 30u8, 110u8, 52u8, 131u8, 130u8, 218u8, 255u8, 22u8, 110u8, 126u8, 135u8, 31u8, 142u8, 137u8, 112u8, 48u8, 64u8, 130u8, 139u8, 167u8, 246u8, 154u8, 3u8, 252u8, 255u8, 123u8, 74u8, 180u8, 45u8, 127u8, 71u8, 157u8, 141u8, 139u8, 153u8, 23u8, 105u8, 248u8, 231u8, 69u8, 210u8, 65u8, 245u8, 198u8, 19u8, 140u8, 120u8, 203u8, 137u8, 172u8, 30u8, 44u8, 47u8, 21u8, 225u8, 140u8, 0u8, 35u8, 141u8, 46u8, 248u8, 226u8, 176u8, 3u8, 145u8, 194u8, 179u8, 232u8, 110u8, 106u8, 190u8, 41u8, 115u8, 238u8, 7u8, 161u8, 236u8, 57u8, 168u8, 125u8, 87u8, 88u8, 22u8, 30u8, 217u8, 109u8, 167u8, 66u8, 193u8, 105u8, 111u8, 39u8, 10u8, 165u8, 80u8, 161u8, 136u8, 100u8, 89u8, 214u8, 46u8, 126u8, 37u8, 86u8, 44u8, 58u8, 90u8, 165u8, 155u8, 161u8, 68u8, 182u8, 226u8, 163u8, 11u8, 7u8, 217u8, 83u8, 68u8, 6u8, 143u8, 144u8, 203u8, 180u8, 235u8, 140u8, 97u8, 163u8, 127u8, 96u8, 158u8, 236u8, 129u8, 177u8, 12u8, 77u8, 215u8, 231u8, 120u8, 222u8, 52u8, 248u8, 219u8, 135u8, 48u8, 142u8, 160u8, 3u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 92u8, 25u8, 107u8, 232u8, 25u8, 59u8, 145u8, 147u8, 242u8, 158u8, 220u8, 97u8, 213u8, 52u8, 175u8, 25u8, 232u8, 239u8, 70u8, 198u8, 208u8, 191u8, 240u8, 53u8, 211u8, 37u8, 92u8, 64u8, 153u8, 138u8, 46u8, 28u8, 47u8, 243u8, 185u8, 85u8, 218u8, 94u8, 77u8, 101u8, 75u8, 18u8, 73u8, 116u8, 64u8, 53u8, 57u8, 1u8, 45u8, 130u8, 114u8, 43u8, 13u8, 125u8, 209u8, 130u8, 211u8, 103u8, 214u8, 40u8, 181u8, 89u8, 126u8, 47u8, 14u8, 239u8, 104u8, 49u8, 131u8, 89u8, 2u8, 122u8, 1u8, 32u8, 47u8, 202u8, 203u8, 135u8, 49u8, 140u8, 158u8, 21u8, 223u8, 138u8, 189u8, 81u8, 177u8, 73u8, 219u8, 60u8, 237u8, 23u8, 116u8, 89u8, 102u8, 34u8];
        
        let ctx = test_scenario::ctx(&mut scenario);
        proximity::init_verifying_key(&server_cap, vk_bytes, ctx);
        
        test_scenario::return_to_sender(&scenario, server_cap);
    };

    // Create commitment
    scenario.next_tx(@0x1);
    {
        let server_cap = test_scenario::take_from_sender<proximity::ServerCap>(&scenario);
        let commitment_bytes = vector[248u8, 131u8, 40u8, 89u8, 23u8, 32u8, 57u8, 7u8, 52u8, 90u8, 245u8, 13u8, 132u8, 70u8, 39u8, 31u8, 172u8, 39u8, 109u8, 47u8, 128u8, 57u8, 248u8, 189u8, 14u8, 208u8, 38u8, 64u8, 230u8, 48u8, 88u8, 31u8];
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
        let proof_bytes = vector[131u8, 95u8, 56u8, 63u8, 237u8, 79u8, 97u8, 21u8, 26u8, 232u8, 246u8, 184u8, 120u8, 193u8, 222u8, 2u8, 115u8, 72u8, 223u8, 181u8, 130u8, 192u8, 126u8, 186u8, 84u8, 94u8, 156u8, 160u8, 231u8, 225u8, 240u8, 23u8, 163u8, 27u8, 230u8, 76u8, 15u8, 225u8, 72u8, 15u8, 201u8, 80u8, 140u8, 19u8, 6u8, 22u8, 82u8, 96u8, 112u8, 107u8, 234u8, 224u8, 216u8, 140u8, 30u8, 255u8, 82u8, 151u8, 93u8, 227u8, 204u8, 51u8, 96u8, 8u8, 27u8, 79u8, 209u8, 58u8, 123u8, 233u8, 135u8, 112u8, 159u8, 221u8, 49u8, 34u8, 135u8, 174u8, 33u8, 57u8, 37u8, 252u8, 97u8, 193u8, 75u8, 218u8, 192u8, 12u8, 226u8, 17u8, 131u8, 37u8, 81u8, 182u8, 238u8, 148u8, 91u8, 112u8, 244u8, 106u8, 136u8, 27u8, 91u8, 133u8, 143u8, 208u8, 0u8, 26u8, 232u8, 92u8, 225u8, 30u8, 89u8, 181u8, 45u8, 5u8, 97u8, 207u8, 228u8, 235u8, 241u8, 195u8, 251u8, 221u8, 64u8, 58u8, 148u8, 10u8];
        let public_inputs = vector[248u8, 131u8, 40u8, 89u8, 23u8, 32u8, 57u8, 7u8, 52u8, 90u8, 245u8, 13u8, 132u8, 70u8, 39u8, 31u8, 83u8, 39u8, 109u8, 47u8, 128u8, 57u8, 248u8, 189u8, 14u8, 208u8, 38u8, 64u8, 230u8, 48u8, 88u8, 31u8, 0u8, 225u8, 245u8, 5u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8]; // Wrong public inputs
        
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
        let vk_bytes = vector[23u8, 138u8, 155u8, 211u8, 67u8, 147u8, 133u8, 109u8, 1u8, 62u8, 99u8, 159u8, 233u8, 140u8, 53u8, 36u8, 14u8, 4u8, 128u8, 106u8, 179u8, 107u8, 187u8, 219u8, 16u8, 225u8, 10u8, 148u8, 192u8, 15u8, 51u8, 161u8, 116u8, 39u8, 237u8, 32u8, 178u8, 228u8, 151u8, 22u8, 220u8, 200u8, 125u8, 69u8, 131u8, 8u8, 12u8, 206u8, 0u8, 229u8, 227u8, 178u8, 170u8, 243u8, 186u8, 163u8, 128u8, 210u8, 153u8, 102u8, 26u8, 82u8, 24u8, 43u8, 228u8, 232u8, 104u8, 21u8, 142u8, 99u8, 80u8, 144u8, 104u8, 28u8, 42u8, 24u8, 253u8, 30u8, 110u8, 52u8, 131u8, 130u8, 218u8, 255u8, 22u8, 110u8, 126u8, 135u8, 31u8, 142u8, 137u8, 112u8, 48u8, 64u8, 130u8, 139u8, 167u8, 246u8, 154u8, 3u8, 252u8, 255u8, 123u8, 74u8, 180u8, 45u8, 127u8, 71u8, 157u8, 141u8, 139u8, 153u8, 23u8, 105u8, 248u8, 231u8, 69u8, 210u8, 65u8, 245u8, 198u8, 19u8, 140u8, 120u8, 203u8, 137u8, 172u8, 30u8, 44u8, 47u8, 21u8, 225u8, 140u8, 0u8, 35u8, 141u8, 46u8, 248u8, 226u8, 176u8, 3u8, 145u8, 194u8, 179u8, 232u8, 110u8, 106u8, 190u8, 41u8, 115u8, 238u8, 7u8, 161u8, 236u8, 57u8, 168u8, 125u8, 87u8, 88u8, 22u8, 30u8, 217u8, 109u8, 167u8, 66u8, 193u8, 105u8, 111u8, 39u8, 10u8, 165u8, 80u8, 161u8, 136u8, 100u8, 89u8, 214u8, 46u8, 126u8, 37u8, 86u8, 44u8, 58u8, 90u8, 165u8, 155u8, 161u8, 68u8, 182u8, 226u8, 163u8, 11u8, 7u8, 217u8, 83u8, 68u8, 6u8, 143u8, 144u8, 203u8, 180u8, 235u8, 140u8, 97u8, 163u8, 127u8, 96u8, 158u8, 236u8, 129u8, 177u8, 12u8, 77u8, 215u8, 231u8, 120u8, 222u8, 52u8, 248u8, 219u8, 135u8, 48u8, 142u8, 160u8, 3u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 92u8, 25u8, 107u8, 232u8, 25u8, 59u8, 145u8, 147u8, 242u8, 158u8, 220u8, 97u8, 213u8, 52u8, 175u8, 25u8, 232u8, 239u8, 70u8, 198u8, 208u8, 191u8, 240u8, 53u8, 211u8, 37u8, 92u8, 64u8, 153u8, 138u8, 46u8, 28u8, 47u8, 243u8, 185u8, 85u8, 218u8, 94u8, 77u8, 101u8, 75u8, 18u8, 73u8, 116u8, 64u8, 53u8, 57u8, 1u8, 45u8, 130u8, 114u8, 43u8, 13u8, 125u8, 209u8, 130u8, 211u8, 103u8, 214u8, 40u8, 181u8, 89u8, 126u8, 47u8, 14u8, 239u8, 104u8, 49u8, 131u8, 89u8, 2u8, 122u8, 1u8, 32u8, 47u8, 202u8, 203u8, 135u8, 49u8, 140u8, 158u8, 21u8, 223u8, 138u8, 189u8, 81u8, 177u8, 73u8, 219u8, 60u8, 237u8, 23u8, 116u8, 89u8, 102u8, 34u8];
        
        let ctx = test_scenario::ctx(&mut scenario);
        proximity::init_verifying_key(&server_cap, vk_bytes, ctx);
        
        test_scenario::return_to_sender(&scenario, server_cap);
    };

    // Create commitment with different coordinates
    scenario.next_tx(@0x1);
    {
        let server_cap = test_scenario::take_from_sender<proximity::ServerCap>(&scenario);
        let commitment_bytes = vector[10u8, 121u8, 191u8, 155u8, 194u8, 43u8, 237u8, 27u8, 170u8, 71u8, 126u8, 88u8, 16u8, 38u8, 124u8, 89u8, 87u8, 137u8, 48u8, 254u8, 79u8, 159u8, 213u8, 60u8, 199u8, 218u8, 215u8, 254u8, 211u8, 55u8, 89u8, 13u8]; // Different Poseidon commitment hash (32 bytes)
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
        let proof_bytes = vector[76u8, 125u8, 52u8, 224u8, 39u8, 232u8, 82u8, 230u8, 193u8, 172u8, 31u8, 62u8, 47u8, 183u8, 180u8, 214u8, 162u8, 3u8, 78u8, 186u8, 50u8, 121u8, 49u8, 141u8, 73u8, 1u8, 41u8, 194u8, 21u8, 116u8, 15u8, 39u8, 137u8, 111u8, 109u8, 204u8, 41u8, 131u8, 124u8, 183u8, 99u8, 124u8, 64u8, 53u8, 49u8, 178u8, 51u8, 165u8, 222u8, 91u8, 180u8, 31u8, 184u8, 196u8, 178u8, 102u8, 4u8, 151u8, 64u8, 200u8, 23u8, 185u8, 31u8, 5u8, 11u8, 21u8, 231u8, 152u8, 229u8, 251u8, 1u8, 210u8, 44u8, 128u8, 121u8, 152u8, 97u8, 224u8, 177u8, 213u8, 5u8, 252u8, 176u8, 48u8, 48u8, 170u8, 9u8, 225u8, 118u8, 142u8, 158u8, 242u8, 155u8, 132u8, 178u8, 10u8, 232u8, 44u8, 248u8, 172u8, 20u8, 107u8, 172u8, 132u8, 178u8, 99u8, 64u8, 193u8, 183u8, 99u8, 156u8, 67u8, 101u8, 72u8, 239u8, 221u8, 92u8, 137u8, 97u8, 25u8, 11u8, 34u8, 237u8, 43u8, 149u8, 240u8, 128u8, 2u8];
        let public_inputs = vector[10u8, 121u8, 191u8, 155u8, 194u8, 43u8, 237u8, 27u8, 170u8, 71u8, 126u8, 88u8, 16u8, 38u8, 124u8, 89u8, 87u8, 137u8, 48u8, 254u8, 79u8, 159u8, 213u8, 60u8, 199u8, 218u8, 215u8, 254u8, 211u8, 55u8, 89u8, 13u8, 0u8, 225u8, 245u8, 5u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8];
        
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
        let vk_bytes = vector[23u8, 138u8, 155u8, 211u8, 67u8, 147u8, 133u8, 109u8, 1u8, 62u8, 99u8, 159u8, 233u8, 140u8, 53u8, 36u8, 14u8, 4u8, 128u8, 106u8, 179u8, 107u8, 187u8, 219u8, 16u8, 225u8, 10u8, 148u8, 192u8, 15u8, 51u8, 161u8, 116u8, 39u8, 237u8, 32u8, 178u8, 228u8, 151u8, 22u8, 220u8, 200u8, 125u8, 69u8, 131u8, 8u8, 12u8, 206u8, 0u8, 229u8, 227u8, 178u8, 170u8, 243u8, 186u8, 163u8, 128u8, 210u8, 153u8, 102u8, 26u8, 82u8, 24u8, 43u8, 228u8, 232u8, 104u8, 21u8, 142u8, 99u8, 80u8, 144u8, 104u8, 28u8, 42u8, 24u8, 253u8, 30u8, 110u8, 52u8, 131u8, 130u8, 218u8, 255u8, 22u8, 110u8, 126u8, 135u8, 31u8, 142u8, 137u8, 112u8, 48u8, 64u8, 130u8, 139u8, 167u8, 246u8, 154u8, 3u8, 252u8, 255u8, 123u8, 74u8, 180u8, 45u8, 127u8, 71u8, 157u8, 141u8, 139u8, 153u8, 23u8, 105u8, 248u8, 231u8, 69u8, 210u8, 65u8, 245u8, 198u8, 19u8, 140u8, 120u8, 203u8, 137u8, 172u8, 30u8, 44u8, 47u8, 21u8, 225u8, 140u8, 0u8, 35u8, 141u8, 46u8, 248u8, 226u8, 176u8, 3u8, 145u8, 194u8, 179u8, 232u8, 110u8, 106u8, 190u8, 41u8, 115u8, 238u8, 7u8, 161u8, 236u8, 57u8, 168u8, 125u8, 87u8, 88u8, 22u8, 30u8, 217u8, 109u8, 167u8, 66u8, 193u8, 105u8, 111u8, 39u8, 10u8, 165u8, 80u8, 161u8, 136u8, 100u8, 89u8, 214u8, 46u8, 126u8, 37u8, 86u8, 44u8, 58u8, 90u8, 165u8, 155u8, 161u8, 68u8, 182u8, 226u8, 163u8, 11u8, 7u8, 217u8, 83u8, 68u8, 6u8, 143u8, 144u8, 203u8, 180u8, 235u8, 140u8, 97u8, 163u8, 127u8, 96u8, 158u8, 236u8, 129u8, 177u8, 12u8, 77u8, 215u8, 231u8, 120u8, 222u8, 52u8, 248u8, 219u8, 135u8, 48u8, 142u8, 160u8, 3u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 92u8, 25u8, 107u8, 232u8, 25u8, 59u8, 145u8, 147u8, 242u8, 158u8, 220u8, 97u8, 213u8, 52u8, 175u8, 25u8, 232u8, 239u8, 70u8, 198u8, 208u8, 191u8, 240u8, 53u8, 211u8, 37u8, 92u8, 64u8, 153u8, 138u8, 46u8, 28u8, 47u8, 243u8, 185u8, 85u8, 218u8, 94u8, 77u8, 101u8, 75u8, 18u8, 73u8, 116u8, 64u8, 53u8, 57u8, 1u8, 45u8, 130u8, 114u8, 43u8, 13u8, 125u8, 209u8, 130u8, 211u8, 103u8, 214u8, 40u8, 181u8, 89u8, 126u8, 47u8, 14u8, 239u8, 104u8, 49u8, 131u8, 89u8, 2u8, 122u8, 1u8, 32u8, 47u8, 202u8, 203u8, 135u8, 49u8, 140u8, 158u8, 21u8, 223u8, 138u8, 189u8, 81u8, 177u8, 73u8, 219u8, 60u8, 237u8, 23u8, 116u8, 89u8, 102u8, 34u8];
        
        let ctx = test_scenario::ctx(&mut scenario);
        proximity::init_verifying_key(&server_cap, vk_bytes, ctx);
        
        test_scenario::return_to_sender(&scenario, server_cap);
    };

    // Create commitment with absolute value coordinates
    scenario.next_tx(@0x1);
    {
        let server_cap = test_scenario::take_from_sender<proximity::ServerCap>(&scenario);
        let commitment_bytes = vector[23u8, 199u8, 201u8, 174u8, 63u8, 182u8, 106u8, 8u8, 72u8, 237u8, 78u8, 23u8, 157u8, 78u8, 142u8, 190u8, 66u8, 36u8, 112u8, 68u8, 208u8, 248u8, 12u8, 220u8, 9u8, 235u8, 247u8, 100u8, 82u8, 208u8, 47u8, 30u8]; // Absolute value Poseidon commitment hash (32 bytes)
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
        let proof_bytes = vector[153u8, 232u8, 227u8, 45u8, 74u8, 136u8, 248u8, 33u8, 67u8, 181u8, 170u8, 39u8, 213u8, 152u8, 6u8, 25u8, 226u8, 193u8, 253u8, 84u8, 53u8, 66u8, 56u8, 233u8, 84u8, 146u8, 42u8, 198u8, 142u8, 251u8, 251u8, 21u8, 214u8, 106u8, 136u8, 248u8, 4u8, 51u8, 57u8, 174u8, 195u8, 111u8, 172u8, 151u8, 193u8, 66u8, 144u8, 197u8, 213u8, 64u8, 237u8, 148u8, 177u8, 88u8, 100u8, 214u8, 57u8, 175u8, 88u8, 211u8, 195u8, 219u8, 70u8, 23u8, 24u8, 96u8, 56u8, 9u8, 178u8, 166u8, 33u8, 214u8, 230u8, 81u8, 186u8, 249u8, 176u8, 108u8, 148u8, 140u8, 233u8, 40u8, 106u8, 249u8, 2u8, 50u8, 86u8, 129u8, 117u8, 136u8, 100u8, 5u8, 102u8, 102u8, 79u8, 167u8, 82u8, 215u8, 112u8, 83u8, 148u8, 169u8, 235u8, 142u8, 37u8, 221u8, 168u8, 143u8, 3u8, 211u8, 201u8, 131u8, 216u8, 3u8, 22u8, 138u8, 1u8, 176u8, 52u8, 203u8, 245u8, 116u8, 128u8, 78u8, 33u8, 134u8, 190u8, 16u8];
        let public_inputs = vector[23u8, 199u8, 201u8, 174u8, 63u8, 182u8, 106u8, 8u8, 72u8, 237u8, 78u8, 23u8, 157u8, 78u8, 142u8, 190u8, 66u8, 36u8, 112u8, 68u8, 208u8, 248u8, 12u8, 220u8, 9u8, 235u8, 247u8, 100u8, 82u8, 208u8, 47u8, 30u8, 0u8, 225u8, 245u8, 5u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8];
        
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
        let vk_bytes = vector[23u8, 138u8, 155u8, 211u8, 67u8, 147u8, 133u8, 109u8, 1u8, 62u8, 99u8, 159u8, 233u8, 140u8, 53u8, 36u8, 14u8, 4u8, 128u8, 106u8, 179u8, 107u8, 187u8, 219u8, 16u8, 225u8, 10u8, 148u8, 192u8, 15u8, 51u8, 161u8, 116u8, 39u8, 237u8, 32u8, 178u8, 228u8, 151u8, 22u8, 220u8, 200u8, 125u8, 69u8, 131u8, 8u8, 12u8, 206u8, 0u8, 229u8, 227u8, 178u8, 170u8, 243u8, 186u8, 163u8, 128u8, 210u8, 153u8, 102u8, 26u8, 82u8, 24u8, 43u8, 228u8, 232u8, 104u8, 21u8, 142u8, 99u8, 80u8, 144u8, 104u8, 28u8, 42u8, 24u8, 253u8, 30u8, 110u8, 52u8, 131u8, 130u8, 218u8, 255u8, 22u8, 110u8, 126u8, 135u8, 31u8, 142u8, 137u8, 112u8, 48u8, 64u8, 130u8, 139u8, 167u8, 246u8, 154u8, 3u8, 252u8, 255u8, 123u8, 74u8, 180u8, 45u8, 127u8, 71u8, 157u8, 141u8, 139u8, 153u8, 23u8, 105u8, 248u8, 231u8, 69u8, 210u8, 65u8, 245u8, 198u8, 19u8, 140u8, 120u8, 203u8, 137u8, 172u8, 30u8, 44u8, 47u8, 21u8, 225u8, 140u8, 0u8, 35u8, 141u8, 46u8, 248u8, 226u8, 176u8, 3u8, 145u8, 194u8, 179u8, 232u8, 110u8, 106u8, 190u8, 41u8, 115u8, 238u8, 7u8, 161u8, 236u8, 57u8, 168u8, 125u8, 87u8, 88u8, 22u8, 30u8, 217u8, 109u8, 167u8, 66u8, 193u8, 105u8, 111u8, 39u8, 10u8, 165u8, 80u8, 161u8, 136u8, 100u8, 89u8, 214u8, 46u8, 126u8, 37u8, 86u8, 44u8, 58u8, 90u8, 165u8, 155u8, 161u8, 68u8, 182u8, 226u8, 163u8, 11u8, 7u8, 217u8, 83u8, 68u8, 6u8, 143u8, 144u8, 203u8, 180u8, 235u8, 140u8, 97u8, 163u8, 127u8, 96u8, 158u8, 236u8, 129u8, 177u8, 12u8, 77u8, 215u8, 231u8, 120u8, 222u8, 52u8, 248u8, 219u8, 135u8, 48u8, 142u8, 160u8, 3u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 92u8, 25u8, 107u8, 232u8, 25u8, 59u8, 145u8, 147u8, 242u8, 158u8, 220u8, 97u8, 213u8, 52u8, 175u8, 25u8, 232u8, 239u8, 70u8, 198u8, 208u8, 191u8, 240u8, 53u8, 211u8, 37u8, 92u8, 64u8, 153u8, 138u8, 46u8, 28u8, 47u8, 243u8, 185u8, 85u8, 218u8, 94u8, 77u8, 101u8, 75u8, 18u8, 73u8, 116u8, 64u8, 53u8, 57u8, 1u8, 45u8, 130u8, 114u8, 43u8, 13u8, 125u8, 209u8, 130u8, 211u8, 103u8, 214u8, 40u8, 181u8, 89u8, 126u8, 47u8, 14u8, 239u8, 104u8, 49u8, 131u8, 89u8, 2u8, 122u8, 1u8, 32u8, 47u8, 202u8, 203u8, 135u8, 49u8, 140u8, 158u8, 21u8, 223u8, 138u8, 189u8, 81u8, 177u8, 73u8, 219u8, 60u8, 237u8, 23u8, 116u8, 89u8, 102u8, 34u8];
        
        let ctx = test_scenario::ctx(&mut scenario);
        proximity::init_verifying_key(&server_cap, vk_bytes, ctx);
        
        test_scenario::return_to_sender(&scenario, server_cap);
    };

    // Create commitment with SSU_B hash
    scenario.next_tx(@0x1);
    {
        let server_cap = test_scenario::take_from_sender<proximity::ServerCap>(&scenario);
        let commitment_b_bytes = vector[10u8, 121u8, 191u8, 155u8, 194u8, 43u8, 237u8, 27u8, 170u8, 71u8, 126u8, 88u8, 16u8, 38u8, 124u8, 89u8, 87u8, 137u8, 48u8, 254u8, 79u8, 159u8, 213u8, 60u8, 199u8, 218u8, 215u8, 254u8, 211u8, 55u8, 89u8, 13u8]; // SSU_B commitment hash
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
        
        let proof_for_ssu_a = vector[131u8, 95u8, 56u8, 63u8, 237u8, 79u8, 97u8, 21u8, 26u8, 232u8, 246u8, 184u8, 120u8, 193u8, 222u8, 2u8, 115u8, 72u8, 223u8, 181u8, 130u8, 192u8, 126u8, 186u8, 84u8, 94u8, 156u8, 160u8, 231u8, 225u8, 240u8, 23u8, 163u8, 27u8, 230u8, 76u8, 15u8, 225u8, 72u8, 15u8, 201u8, 80u8, 140u8, 19u8, 6u8, 22u8, 82u8, 96u8, 112u8, 107u8, 234u8, 224u8, 216u8, 140u8, 30u8, 255u8, 82u8, 151u8, 93u8, 227u8, 204u8, 51u8, 96u8, 8u8, 27u8, 79u8, 209u8, 58u8, 123u8, 233u8, 135u8, 112u8, 159u8, 221u8, 49u8, 34u8, 135u8, 174u8, 33u8, 57u8, 37u8, 252u8, 97u8, 193u8, 75u8, 218u8, 192u8, 12u8, 226u8, 17u8, 131u8, 37u8, 81u8, 182u8, 238u8, 148u8, 91u8, 112u8, 244u8, 106u8, 136u8, 27u8, 91u8, 133u8, 143u8, 208u8, 0u8, 26u8, 232u8, 92u8, 225u8, 30u8, 89u8, 181u8, 45u8, 5u8, 97u8, 207u8, 228u8, 235u8, 241u8, 195u8, 251u8, 221u8, 64u8, 58u8, 148u8, 10u8]; // Valid proof for SSU_A
        let public_inputs_for_ssu_a = vector[248u8, 131u8, 40u8, 89u8, 23u8, 32u8, 57u8, 7u8, 52u8, 90u8, 245u8, 13u8, 132u8, 70u8, 39u8, 31u8, 172u8, 39u8, 109u8, 47u8, 128u8, 57u8, 248u8, 189u8, 14u8, 208u8, 38u8, 64u8, 230u8, 48u8, 88u8, 31u8, 0u8, 225u8, 245u8, 5u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8]; // Public inputs containing SSU_A's hash (WRONG!)
        
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
        let vk_bytes = vector[23u8, 138u8, 155u8, 211u8, 67u8, 147u8, 133u8, 109u8, 1u8, 62u8, 99u8, 159u8, 233u8, 140u8, 53u8, 36u8, 14u8, 4u8, 128u8, 106u8, 179u8, 107u8, 187u8, 219u8, 16u8, 225u8, 10u8, 148u8, 192u8, 15u8, 51u8, 161u8, 116u8, 39u8, 237u8, 32u8, 178u8, 228u8, 151u8, 22u8, 220u8, 200u8, 125u8, 69u8, 131u8, 8u8, 12u8, 206u8, 0u8, 229u8, 227u8, 178u8, 170u8, 243u8, 186u8, 163u8, 128u8, 210u8, 153u8, 102u8, 26u8, 82u8, 24u8, 43u8, 228u8, 232u8, 104u8, 21u8, 142u8, 99u8, 80u8, 144u8, 104u8, 28u8, 42u8, 24u8, 253u8, 30u8, 110u8, 52u8, 131u8, 130u8, 218u8, 255u8, 22u8, 110u8, 126u8, 135u8, 31u8, 142u8, 137u8, 112u8, 48u8, 64u8, 130u8, 139u8, 167u8, 246u8, 154u8, 3u8, 252u8, 255u8, 123u8, 74u8, 180u8, 45u8, 127u8, 71u8, 157u8, 141u8, 139u8, 153u8, 23u8, 105u8, 248u8, 231u8, 69u8, 210u8, 65u8, 245u8, 198u8, 19u8, 140u8, 120u8, 203u8, 137u8, 172u8, 30u8, 44u8, 47u8, 21u8, 225u8, 140u8, 0u8, 35u8, 141u8, 46u8, 248u8, 226u8, 176u8, 3u8, 145u8, 194u8, 179u8, 232u8, 110u8, 106u8, 190u8, 41u8, 115u8, 238u8, 7u8, 161u8, 236u8, 57u8, 168u8, 125u8, 87u8, 88u8, 22u8, 30u8, 217u8, 109u8, 167u8, 66u8, 193u8, 105u8, 111u8, 39u8, 10u8, 165u8, 80u8, 161u8, 136u8, 100u8, 89u8, 214u8, 46u8, 126u8, 37u8, 86u8, 44u8, 58u8, 90u8, 165u8, 155u8, 161u8, 68u8, 182u8, 226u8, 163u8, 11u8, 7u8, 217u8, 83u8, 68u8, 6u8, 143u8, 144u8, 203u8, 180u8, 235u8, 140u8, 97u8, 163u8, 127u8, 96u8, 158u8, 236u8, 129u8, 177u8, 12u8, 77u8, 215u8, 231u8, 120u8, 222u8, 52u8, 248u8, 219u8, 135u8, 48u8, 142u8, 160u8, 3u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 92u8, 25u8, 107u8, 232u8, 25u8, 59u8, 145u8, 147u8, 242u8, 158u8, 220u8, 97u8, 213u8, 52u8, 175u8, 25u8, 232u8, 239u8, 70u8, 198u8, 208u8, 191u8, 240u8, 53u8, 211u8, 37u8, 92u8, 64u8, 153u8, 138u8, 46u8, 28u8, 47u8, 243u8, 185u8, 85u8, 218u8, 94u8, 77u8, 101u8, 75u8, 18u8, 73u8, 116u8, 64u8, 53u8, 57u8, 1u8, 45u8, 130u8, 114u8, 43u8, 13u8, 125u8, 209u8, 130u8, 211u8, 103u8, 214u8, 40u8, 181u8, 89u8, 126u8, 47u8, 14u8, 239u8, 104u8, 49u8, 131u8, 89u8, 2u8, 122u8, 1u8, 32u8, 47u8, 202u8, 203u8, 135u8, 49u8, 140u8, 158u8, 21u8, 223u8, 138u8, 189u8, 81u8, 177u8, 73u8, 219u8, 60u8, 237u8, 23u8, 116u8, 89u8, 102u8, 34u8];
        
        let ctx = test_scenario::ctx(&mut scenario);
        proximity::init_verifying_key(&server_cap, vk_bytes, ctx);
        
        test_scenario::return_to_sender(&scenario, server_cap);
    };

    // Create commitment with SSU_A hash
    scenario.next_tx(@0x1);
    {
        let server_cap = test_scenario::take_from_sender<proximity::ServerCap>(&scenario);
        let commitment_bytes = vector[248u8, 131u8, 40u8, 89u8, 23u8, 32u8, 57u8, 7u8, 52u8, 90u8, 245u8, 13u8, 132u8, 70u8, 39u8, 31u8, 172u8, 39u8, 109u8, 47u8, 128u8, 57u8, 248u8, 189u8, 14u8, 208u8, 38u8, 64u8, 230u8, 48u8, 88u8, 31u8]; // SSU_A commitment hash
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
        let proof_bytes = vector[131u8, 95u8, 56u8, 63u8, 237u8, 79u8, 97u8, 21u8, 26u8, 232u8, 246u8, 184u8, 120u8, 193u8, 222u8, 2u8, 115u8, 72u8, 223u8, 181u8, 130u8, 192u8, 126u8, 186u8, 84u8, 94u8, 156u8, 160u8, 231u8, 225u8, 240u8, 23u8, 163u8, 27u8, 230u8, 76u8, 15u8, 225u8, 72u8, 15u8, 201u8, 80u8, 140u8, 19u8, 6u8, 22u8, 82u8, 96u8, 112u8, 107u8, 234u8, 224u8, 216u8, 140u8, 30u8, 255u8, 82u8, 151u8, 93u8, 227u8, 204u8, 51u8, 96u8, 8u8, 27u8, 79u8, 209u8, 58u8, 123u8, 233u8, 135u8, 112u8, 159u8, 221u8, 49u8, 34u8, 135u8, 174u8, 33u8, 57u8, 37u8, 252u8, 97u8, 193u8, 75u8, 218u8, 192u8, 12u8, 226u8, 17u8, 131u8, 37u8, 81u8, 182u8, 238u8, 148u8, 91u8, 112u8, 244u8, 106u8, 136u8, 27u8, 91u8, 133u8, 143u8, 208u8, 0u8, 26u8, 232u8, 92u8, 225u8, 30u8, 89u8, 181u8, 45u8, 5u8, 97u8, 207u8, 228u8, 235u8, 241u8, 195u8, 251u8, 221u8, 64u8, 58u8, 148u8, 10u8]; // Valid proof for SSU_A
        let public_inputs = vector[248u8, 131u8, 40u8, 89u8, 23u8, 32u8, 57u8, 7u8, 52u8, 90u8, 245u8, 13u8, 132u8, 70u8, 39u8, 31u8, 172u8, 39u8, 109u8, 47u8, 128u8, 57u8, 248u8, 189u8, 14u8, 208u8, 38u8, 64u8, 230u8, 48u8, 88u8, 31u8, 0u8, 225u8, 245u8, 5u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8]; // Public inputs with SSU_A hash (CORRECT!)
        
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
