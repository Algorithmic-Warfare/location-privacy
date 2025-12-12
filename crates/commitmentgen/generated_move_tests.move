
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
        let vk_bytes = vector[216u8, 245u8, 57u8, 226u8, 236u8, 255u8, 165u8, 135u8, 13u8, 186u8, 23u8, 109u8, 106u8, 154u8, 133u8, 145u8, 245u8, 93u8, 94u8, 225u8, 181u8, 90u8, 234u8, 59u8, 52u8, 124u8, 81u8, 152u8, 194u8, 162u8, 37u8, 153u8, 62u8, 92u8, 40u8, 97u8, 7u8, 199u8, 184u8, 147u8, 130u8, 8u8, 32u8, 79u8, 253u8, 35u8, 45u8, 252u8, 202u8, 152u8, 113u8, 67u8, 191u8, 30u8, 186u8, 101u8, 22u8, 162u8, 169u8, 53u8, 201u8, 186u8, 111u8, 47u8, 231u8, 251u8, 17u8, 179u8, 57u8, 43u8, 177u8, 195u8, 232u8, 188u8, 52u8, 48u8, 10u8, 197u8, 183u8, 204u8, 164u8, 29u8, 75u8, 164u8, 199u8, 177u8, 27u8, 178u8, 98u8, 179u8, 108u8, 113u8, 112u8, 64u8, 185u8, 31u8, 224u8, 67u8, 33u8, 161u8, 35u8, 32u8, 64u8, 139u8, 104u8, 128u8, 164u8, 91u8, 193u8, 28u8, 146u8, 102u8, 221u8, 44u8, 102u8, 34u8, 188u8, 136u8, 137u8, 77u8, 235u8, 224u8, 255u8, 5u8, 185u8, 227u8, 242u8, 40u8, 136u8, 105u8, 207u8, 236u8, 106u8, 197u8, 149u8, 20u8, 198u8, 165u8, 212u8, 254u8, 231u8, 187u8, 220u8, 165u8, 19u8, 241u8, 198u8, 205u8, 111u8, 197u8, 85u8, 128u8, 60u8, 53u8, 240u8, 154u8, 152u8, 28u8, 113u8, 172u8, 238u8, 239u8, 201u8, 225u8, 60u8, 50u8, 9u8, 111u8, 119u8, 251u8, 89u8, 147u8, 81u8, 172u8, 140u8, 117u8, 166u8, 194u8, 11u8, 84u8, 178u8, 143u8, 51u8, 57u8, 57u8, 121u8, 254u8, 34u8, 244u8, 204u8, 80u8, 37u8, 219u8, 120u8, 129u8, 4u8, 207u8, 71u8, 104u8, 208u8, 250u8, 28u8, 177u8, 136u8, 158u8, 171u8, 24u8, 70u8, 248u8, 157u8, 28u8, 210u8, 3u8, 72u8, 133u8, 9u8, 10u8, 120u8, 232u8, 138u8, 141u8, 99u8, 154u8, 25u8, 3u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 132u8, 64u8, 99u8, 228u8, 137u8, 95u8, 230u8, 102u8, 53u8, 58u8, 83u8, 14u8, 216u8, 63u8, 107u8, 18u8, 32u8, 117u8, 170u8, 76u8, 146u8, 206u8, 115u8, 75u8, 155u8, 163u8, 203u8, 102u8, 83u8, 125u8, 243u8, 145u8, 94u8, 242u8, 230u8, 35u8, 5u8, 49u8, 109u8, 124u8, 244u8, 12u8, 206u8, 231u8, 161u8, 146u8, 22u8, 47u8, 71u8, 77u8, 75u8, 249u8, 48u8, 100u8, 159u8, 168u8, 221u8, 54u8, 39u8, 188u8, 61u8, 30u8, 126u8, 19u8, 196u8, 133u8, 24u8, 232u8, 111u8, 172u8, 33u8, 184u8, 231u8, 211u8, 175u8, 179u8, 254u8, 68u8, 5u8, 206u8, 93u8, 113u8, 139u8, 205u8, 36u8, 62u8, 21u8, 250u8, 145u8, 150u8, 55u8, 139u8, 152u8, 181u8, 45u8, 137u8]; // Canonical verifying key (328 bytes)
        
        let ctx = test_scenario::ctx(&mut scenario);
        proximity::init_verifying_key(&server_cap, vk_bytes, ctx);
        
        test_scenario::return_to_sender(&scenario, server_cap);
    };

    // Create commitment (Poseidon hash - 32 bytes)
    scenario.next_tx(@0x1);
    {
        let server_cap = test_scenario::take_from_sender<proximity::ServerCap>(&scenario);
        let commitment_bytes = vector[82u8, 12u8, 38u8, 49u8, 6u8, 145u8, 99u8, 109u8, 31u8, 187u8, 222u8, 12u8, 75u8, 29u8, 137u8, 83u8, 190u8, 82u8, 88u8, 202u8, 173u8, 63u8, 159u8, 13u8, 5u8, 1u8, 250u8, 37u8, 8u8, 236u8, 85u8, 40u8]; // Poseidon hash (32 bytes)
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
        let proof_bytes = vector[172u8, 16u8, 129u8, 220u8, 153u8, 129u8, 134u8, 240u8, 37u8, 42u8, 226u8, 254u8, 89u8, 5u8, 213u8, 101u8, 96u8, 86u8, 251u8, 147u8, 208u8, 230u8, 109u8, 185u8, 162u8, 25u8, 240u8, 227u8, 162u8, 89u8, 137u8, 164u8, 177u8, 33u8, 7u8, 250u8, 80u8, 124u8, 65u8, 68u8, 7u8, 62u8, 47u8, 248u8, 2u8, 244u8, 223u8, 51u8, 229u8, 35u8, 166u8, 57u8, 106u8, 48u8, 136u8, 148u8, 158u8, 41u8, 107u8, 190u8, 186u8, 254u8, 100u8, 44u8, 77u8, 31u8, 93u8, 197u8, 179u8, 85u8, 207u8, 195u8, 226u8, 164u8, 114u8, 124u8, 216u8, 20u8, 101u8, 201u8, 137u8, 8u8, 21u8, 223u8, 17u8, 179u8, 74u8, 211u8, 173u8, 194u8, 199u8, 125u8, 72u8, 150u8, 136u8, 134u8, 113u8, 113u8, 197u8, 34u8, 222u8, 178u8, 198u8, 4u8, 58u8, 210u8, 94u8, 107u8, 0u8, 68u8, 156u8, 143u8, 165u8, 156u8, 151u8, 134u8, 166u8, 115u8, 178u8, 206u8, 210u8, 231u8, 112u8, 183u8, 229u8, 79u8, 21u8, 33u8];
        let public_inputs = vector[82u8, 12u8, 38u8, 49u8, 6u8, 145u8, 99u8, 109u8, 31u8, 187u8, 222u8, 12u8, 75u8, 29u8, 137u8, 83u8, 190u8, 82u8, 88u8, 202u8, 173u8, 63u8, 159u8, 13u8, 5u8, 1u8, 250u8, 37u8, 8u8, 236u8, 85u8, 40u8, 0u8, 225u8, 245u8, 5u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8]; // [commitment_hash, max_distance_squared] (64 bytes total)
        
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
        let vk_bytes = vector[216u8, 245u8, 57u8, 226u8, 236u8, 255u8, 165u8, 135u8, 13u8, 186u8, 23u8, 109u8, 106u8, 154u8, 133u8, 145u8, 245u8, 93u8, 94u8, 225u8, 181u8, 90u8, 234u8, 59u8, 52u8, 124u8, 81u8, 152u8, 194u8, 162u8, 37u8, 153u8, 62u8, 92u8, 40u8, 97u8, 7u8, 199u8, 184u8, 147u8, 130u8, 8u8, 32u8, 79u8, 253u8, 35u8, 45u8, 252u8, 202u8, 152u8, 113u8, 67u8, 191u8, 30u8, 186u8, 101u8, 22u8, 162u8, 169u8, 53u8, 201u8, 186u8, 111u8, 47u8, 231u8, 251u8, 17u8, 179u8, 57u8, 43u8, 177u8, 195u8, 232u8, 188u8, 52u8, 48u8, 10u8, 197u8, 183u8, 204u8, 164u8, 29u8, 75u8, 164u8, 199u8, 177u8, 27u8, 178u8, 98u8, 179u8, 108u8, 113u8, 112u8, 64u8, 185u8, 31u8, 224u8, 67u8, 33u8, 161u8, 35u8, 32u8, 64u8, 139u8, 104u8, 128u8, 164u8, 91u8, 193u8, 28u8, 146u8, 102u8, 221u8, 44u8, 102u8, 34u8, 188u8, 136u8, 137u8, 77u8, 235u8, 224u8, 255u8, 5u8, 185u8, 227u8, 242u8, 40u8, 136u8, 105u8, 207u8, 236u8, 106u8, 197u8, 149u8, 20u8, 198u8, 165u8, 212u8, 254u8, 231u8, 187u8, 220u8, 165u8, 19u8, 241u8, 198u8, 205u8, 111u8, 197u8, 85u8, 128u8, 60u8, 53u8, 240u8, 154u8, 152u8, 28u8, 113u8, 172u8, 238u8, 239u8, 201u8, 225u8, 60u8, 50u8, 9u8, 111u8, 119u8, 251u8, 89u8, 147u8, 81u8, 172u8, 140u8, 117u8, 166u8, 194u8, 11u8, 84u8, 178u8, 143u8, 51u8, 57u8, 57u8, 121u8, 254u8, 34u8, 244u8, 204u8, 80u8, 37u8, 219u8, 120u8, 129u8, 4u8, 207u8, 71u8, 104u8, 208u8, 250u8, 28u8, 177u8, 136u8, 158u8, 171u8, 24u8, 70u8, 248u8, 157u8, 28u8, 210u8, 3u8, 72u8, 133u8, 9u8, 10u8, 120u8, 232u8, 138u8, 141u8, 99u8, 154u8, 25u8, 3u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 132u8, 64u8, 99u8, 228u8, 137u8, 95u8, 230u8, 102u8, 53u8, 58u8, 83u8, 14u8, 216u8, 63u8, 107u8, 18u8, 32u8, 117u8, 170u8, 76u8, 146u8, 206u8, 115u8, 75u8, 155u8, 163u8, 203u8, 102u8, 83u8, 125u8, 243u8, 145u8, 94u8, 242u8, 230u8, 35u8, 5u8, 49u8, 109u8, 124u8, 244u8, 12u8, 206u8, 231u8, 161u8, 146u8, 22u8, 47u8, 71u8, 77u8, 75u8, 249u8, 48u8, 100u8, 159u8, 168u8, 221u8, 54u8, 39u8, 188u8, 61u8, 30u8, 126u8, 19u8, 196u8, 133u8, 24u8, 232u8, 111u8, 172u8, 33u8, 184u8, 231u8, 211u8, 175u8, 179u8, 254u8, 68u8, 5u8, 206u8, 93u8, 113u8, 139u8, 205u8, 36u8, 62u8, 21u8, 250u8, 145u8, 150u8, 55u8, 139u8, 152u8, 181u8, 45u8, 137u8];
        
        let ctx = test_scenario::ctx(&mut scenario);
        proximity::init_verifying_key(&server_cap, vk_bytes, ctx);
        
        test_scenario::return_to_sender(&scenario, server_cap);
    };

    // Create commitment
    scenario.next_tx(@0x1);
    {
        let server_cap = test_scenario::take_from_sender<proximity::ServerCap>(&scenario);
        let commitment_bytes = vector[82u8, 12u8, 38u8, 49u8, 6u8, 145u8, 99u8, 109u8, 31u8, 187u8, 222u8, 12u8, 75u8, 29u8, 137u8, 83u8, 190u8, 82u8, 88u8, 202u8, 173u8, 63u8, 159u8, 13u8, 5u8, 1u8, 250u8, 37u8, 8u8, 236u8, 85u8, 40u8];
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
        let proof_bytes = vector[172u8, 16u8, 129u8, 220u8, 153u8, 129u8, 134u8, 240u8, 37u8, 42u8, 29u8, 254u8, 89u8, 5u8, 213u8, 101u8, 96u8, 86u8, 251u8, 147u8, 208u8, 230u8, 109u8, 185u8, 162u8, 25u8, 240u8, 227u8, 162u8, 89u8, 137u8, 164u8, 177u8, 33u8, 7u8, 250u8, 80u8, 124u8, 65u8, 68u8, 7u8, 62u8, 47u8, 248u8, 2u8, 244u8, 223u8, 51u8, 229u8, 35u8, 166u8, 57u8, 106u8, 48u8, 136u8, 148u8, 158u8, 41u8, 107u8, 190u8, 186u8, 254u8, 100u8, 44u8, 77u8, 31u8, 93u8, 197u8, 179u8, 85u8, 207u8, 195u8, 226u8, 164u8, 114u8, 124u8, 216u8, 20u8, 101u8, 201u8, 137u8, 8u8, 21u8, 223u8, 17u8, 179u8, 74u8, 211u8, 173u8, 194u8, 199u8, 125u8, 72u8, 150u8, 136u8, 134u8, 113u8, 113u8, 197u8, 34u8, 222u8, 178u8, 198u8, 4u8, 58u8, 210u8, 94u8, 107u8, 0u8, 68u8, 156u8, 143u8, 165u8, 156u8, 151u8, 134u8, 166u8, 115u8, 178u8, 206u8, 210u8, 231u8, 112u8, 183u8, 229u8, 79u8, 21u8, 33u8]; // Corrupted proof bytes
        let public_inputs = vector[82u8, 12u8, 38u8, 49u8, 6u8, 145u8, 99u8, 109u8, 31u8, 187u8, 222u8, 12u8, 75u8, 29u8, 137u8, 83u8, 190u8, 82u8, 88u8, 202u8, 173u8, 63u8, 159u8, 13u8, 5u8, 1u8, 250u8, 37u8, 8u8, 236u8, 85u8, 40u8, 0u8, 225u8, 245u8, 5u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8];
        
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
        let wrong_vk_bytes = vector[25u8, 128u8, 230u8, 168u8, 50u8, 109u8, 182u8, 56u8, 137u8, 142u8, 131u8, 204u8, 109u8, 145u8, 216u8, 65u8, 1u8, 144u8, 230u8, 158u8, 179u8, 228u8, 234u8, 124u8, 121u8, 12u8, 95u8, 28u8, 254u8, 70u8, 237u8, 14u8, 212u8, 135u8, 196u8, 251u8, 69u8, 255u8, 156u8, 190u8, 114u8, 173u8, 17u8, 154u8, 205u8, 76u8, 109u8, 202u8, 230u8, 68u8, 135u8, 240u8, 211u8, 251u8, 46u8, 209u8, 36u8, 52u8, 165u8, 220u8, 225u8, 35u8, 218u8, 14u8, 168u8, 154u8, 122u8, 193u8, 157u8, 84u8, 122u8, 78u8, 60u8, 32u8, 36u8, 112u8, 88u8, 190u8, 109u8, 38u8, 75u8, 254u8, 183u8, 152u8, 164u8, 131u8, 158u8, 249u8, 210u8, 123u8, 214u8, 186u8, 171u8, 204u8, 24u8, 168u8, 144u8, 50u8, 26u8, 104u8, 32u8, 101u8, 146u8, 98u8, 218u8, 175u8, 219u8, 238u8, 0u8, 45u8, 233u8, 120u8, 197u8, 203u8, 90u8, 9u8, 173u8, 125u8, 43u8, 0u8, 91u8, 17u8, 110u8, 40u8, 118u8, 204u8, 241u8, 47u8, 230u8, 33u8, 64u8, 133u8, 147u8, 31u8, 87u8, 40u8, 136u8, 165u8, 128u8, 29u8, 201u8, 229u8, 49u8, 57u8, 201u8, 37u8, 110u8, 150u8, 156u8, 192u8, 223u8, 226u8, 16u8, 214u8, 191u8, 30u8, 226u8, 43u8, 82u8, 12u8, 63u8, 84u8, 217u8, 157u8, 135u8, 102u8, 241u8, 92u8, 222u8, 180u8, 5u8, 232u8, 144u8, 79u8, 68u8, 62u8, 11u8, 255u8, 3u8, 192u8, 125u8, 66u8, 1u8, 222u8, 65u8, 31u8, 239u8, 40u8, 45u8, 49u8, 120u8, 35u8, 77u8, 135u8, 68u8, 43u8, 48u8, 48u8, 131u8, 164u8, 33u8, 207u8, 79u8, 106u8, 143u8, 221u8, 229u8, 122u8, 115u8, 113u8, 155u8, 204u8, 183u8, 29u8, 34u8, 22u8, 154u8, 24u8, 166u8, 65u8, 222u8, 187u8, 96u8, 129u8, 3u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 122u8, 83u8, 173u8, 22u8, 161u8, 198u8, 245u8, 101u8, 214u8, 56u8, 67u8, 123u8, 160u8, 29u8, 21u8, 50u8, 210u8, 198u8, 111u8, 98u8, 191u8, 241u8, 109u8, 57u8, 46u8, 126u8, 175u8, 53u8, 142u8, 108u8, 243u8, 6u8, 128u8, 103u8, 27u8, 158u8, 19u8, 41u8, 138u8, 138u8, 78u8, 42u8, 55u8, 37u8, 100u8, 172u8, 33u8, 123u8, 156u8, 40u8, 14u8, 224u8, 178u8, 188u8, 193u8, 164u8, 252u8, 234u8, 106u8, 230u8, 80u8, 158u8, 90u8, 2u8, 229u8, 228u8, 33u8, 80u8, 131u8, 224u8, 132u8, 193u8, 129u8, 228u8, 184u8, 15u8, 204u8, 41u8, 167u8, 112u8, 151u8, 173u8, 199u8, 80u8, 118u8, 120u8, 167u8, 204u8, 35u8, 245u8, 155u8, 191u8, 20u8, 241u8, 248u8, 47u8]; // Wrong VK bytes (from different trusted setup)
        
        let ctx = test_scenario::ctx(&mut scenario);
        proximity::init_verifying_key(&server_cap, wrong_vk_bytes, ctx);
        
        test_scenario::return_to_sender(&scenario, server_cap);
    };

    // Create commitment
    scenario.next_tx(@0x1);
    {
        let server_cap = test_scenario::take_from_sender<proximity::ServerCap>(&scenario);
        let commitment_bytes = vector[82u8, 12u8, 38u8, 49u8, 6u8, 145u8, 99u8, 109u8, 31u8, 187u8, 222u8, 12u8, 75u8, 29u8, 137u8, 83u8, 190u8, 82u8, 88u8, 202u8, 173u8, 63u8, 159u8, 13u8, 5u8, 1u8, 250u8, 37u8, 8u8, 236u8, 85u8, 40u8];
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
        let proof_bytes = vector[172u8, 16u8, 129u8, 220u8, 153u8, 129u8, 134u8, 240u8, 37u8, 42u8, 226u8, 254u8, 89u8, 5u8, 213u8, 101u8, 96u8, 86u8, 251u8, 147u8, 208u8, 230u8, 109u8, 185u8, 162u8, 25u8, 240u8, 227u8, 162u8, 89u8, 137u8, 164u8, 177u8, 33u8, 7u8, 250u8, 80u8, 124u8, 65u8, 68u8, 7u8, 62u8, 47u8, 248u8, 2u8, 244u8, 223u8, 51u8, 229u8, 35u8, 166u8, 57u8, 106u8, 48u8, 136u8, 148u8, 158u8, 41u8, 107u8, 190u8, 186u8, 254u8, 100u8, 44u8, 77u8, 31u8, 93u8, 197u8, 179u8, 85u8, 207u8, 195u8, 226u8, 164u8, 114u8, 124u8, 216u8, 20u8, 101u8, 201u8, 137u8, 8u8, 21u8, 223u8, 17u8, 179u8, 74u8, 211u8, 173u8, 194u8, 199u8, 125u8, 72u8, 150u8, 136u8, 134u8, 113u8, 113u8, 197u8, 34u8, 222u8, 178u8, 198u8, 4u8, 58u8, 210u8, 94u8, 107u8, 0u8, 68u8, 156u8, 143u8, 165u8, 156u8, 151u8, 134u8, 166u8, 115u8, 178u8, 206u8, 210u8, 231u8, 112u8, 183u8, 229u8, 79u8, 21u8, 33u8]; // Proof generated with correct VK
        let public_inputs = vector[82u8, 12u8, 38u8, 49u8, 6u8, 145u8, 99u8, 109u8, 31u8, 187u8, 222u8, 12u8, 75u8, 29u8, 137u8, 83u8, 190u8, 82u8, 88u8, 202u8, 173u8, 63u8, 159u8, 13u8, 5u8, 1u8, 250u8, 37u8, 8u8, 236u8, 85u8, 40u8, 0u8, 225u8, 245u8, 5u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8];
        
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
        let vk_bytes = vector[216u8, 245u8, 57u8, 226u8, 236u8, 255u8, 165u8, 135u8, 13u8, 186u8, 23u8, 109u8, 106u8, 154u8, 133u8, 145u8, 245u8, 93u8, 94u8, 225u8, 181u8, 90u8, 234u8, 59u8, 52u8, 124u8, 81u8, 152u8, 194u8, 162u8, 37u8, 153u8, 62u8, 92u8, 40u8, 97u8, 7u8, 199u8, 184u8, 147u8, 130u8, 8u8, 32u8, 79u8, 253u8, 35u8, 45u8, 252u8, 202u8, 152u8, 113u8, 67u8, 191u8, 30u8, 186u8, 101u8, 22u8, 162u8, 169u8, 53u8, 201u8, 186u8, 111u8, 47u8, 231u8, 251u8, 17u8, 179u8, 57u8, 43u8, 177u8, 195u8, 232u8, 188u8, 52u8, 48u8, 10u8, 197u8, 183u8, 204u8, 164u8, 29u8, 75u8, 164u8, 199u8, 177u8, 27u8, 178u8, 98u8, 179u8, 108u8, 113u8, 112u8, 64u8, 185u8, 31u8, 224u8, 67u8, 33u8, 161u8, 35u8, 32u8, 64u8, 139u8, 104u8, 128u8, 164u8, 91u8, 193u8, 28u8, 146u8, 102u8, 221u8, 44u8, 102u8, 34u8, 188u8, 136u8, 137u8, 77u8, 235u8, 224u8, 255u8, 5u8, 185u8, 227u8, 242u8, 40u8, 136u8, 105u8, 207u8, 236u8, 106u8, 197u8, 149u8, 20u8, 198u8, 165u8, 212u8, 254u8, 231u8, 187u8, 220u8, 165u8, 19u8, 241u8, 198u8, 205u8, 111u8, 197u8, 85u8, 128u8, 60u8, 53u8, 240u8, 154u8, 152u8, 28u8, 113u8, 172u8, 238u8, 239u8, 201u8, 225u8, 60u8, 50u8, 9u8, 111u8, 119u8, 251u8, 89u8, 147u8, 81u8, 172u8, 140u8, 117u8, 166u8, 194u8, 11u8, 84u8, 178u8, 143u8, 51u8, 57u8, 57u8, 121u8, 254u8, 34u8, 244u8, 204u8, 80u8, 37u8, 219u8, 120u8, 129u8, 4u8, 207u8, 71u8, 104u8, 208u8, 250u8, 28u8, 177u8, 136u8, 158u8, 171u8, 24u8, 70u8, 248u8, 157u8, 28u8, 210u8, 3u8, 72u8, 133u8, 9u8, 10u8, 120u8, 232u8, 138u8, 141u8, 99u8, 154u8, 25u8, 3u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 132u8, 64u8, 99u8, 228u8, 137u8, 95u8, 230u8, 102u8, 53u8, 58u8, 83u8, 14u8, 216u8, 63u8, 107u8, 18u8, 32u8, 117u8, 170u8, 76u8, 146u8, 206u8, 115u8, 75u8, 155u8, 163u8, 203u8, 102u8, 83u8, 125u8, 243u8, 145u8, 94u8, 242u8, 230u8, 35u8, 5u8, 49u8, 109u8, 124u8, 244u8, 12u8, 206u8, 231u8, 161u8, 146u8, 22u8, 47u8, 71u8, 77u8, 75u8, 249u8, 48u8, 100u8, 159u8, 168u8, 221u8, 54u8, 39u8, 188u8, 61u8, 30u8, 126u8, 19u8, 196u8, 133u8, 24u8, 232u8, 111u8, 172u8, 33u8, 184u8, 231u8, 211u8, 175u8, 179u8, 254u8, 68u8, 5u8, 206u8, 93u8, 113u8, 139u8, 205u8, 36u8, 62u8, 21u8, 250u8, 145u8, 150u8, 55u8, 139u8, 152u8, 181u8, 45u8, 137u8];
        
        let ctx = test_scenario::ctx(&mut scenario);
        proximity::init_verifying_key(&server_cap, vk_bytes, ctx);
        
        test_scenario::return_to_sender(&scenario, server_cap);
    };

    // Create commitment
    scenario.next_tx(@0x1);
    {
        let server_cap = test_scenario::take_from_sender<proximity::ServerCap>(&scenario);
        let commitment_bytes = vector[82u8, 12u8, 38u8, 49u8, 6u8, 145u8, 99u8, 109u8, 31u8, 187u8, 222u8, 12u8, 75u8, 29u8, 137u8, 83u8, 190u8, 82u8, 88u8, 202u8, 173u8, 63u8, 159u8, 13u8, 5u8, 1u8, 250u8, 37u8, 8u8, 236u8, 85u8, 40u8];
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
        let proof_bytes = vector[172u8, 16u8, 129u8, 220u8, 153u8, 129u8, 134u8, 240u8, 37u8, 42u8, 226u8, 254u8, 89u8, 5u8, 213u8, 101u8, 96u8, 86u8, 251u8, 147u8, 208u8, 230u8, 109u8, 185u8, 162u8, 25u8, 240u8, 227u8, 162u8, 89u8, 137u8, 164u8, 177u8, 33u8, 7u8, 250u8, 80u8, 124u8, 65u8, 68u8, 7u8, 62u8, 47u8, 248u8, 2u8, 244u8, 223u8, 51u8, 229u8, 35u8, 166u8, 57u8, 106u8, 48u8, 136u8, 148u8, 158u8, 41u8, 107u8, 190u8, 186u8, 254u8, 100u8, 44u8, 77u8, 31u8, 93u8, 197u8, 179u8, 85u8, 207u8, 195u8, 226u8, 164u8, 114u8, 124u8, 216u8, 20u8, 101u8, 201u8, 137u8, 8u8, 21u8, 223u8, 17u8, 179u8, 74u8, 211u8, 173u8, 194u8, 199u8, 125u8, 72u8, 150u8, 136u8, 134u8, 113u8, 113u8, 197u8, 34u8, 222u8, 178u8, 198u8, 4u8, 58u8, 210u8, 94u8, 107u8, 0u8, 68u8, 156u8, 143u8, 165u8, 156u8, 151u8, 134u8, 166u8, 115u8, 178u8, 206u8, 210u8, 231u8, 112u8, 183u8, 229u8, 79u8, 21u8, 33u8];
        let public_inputs = vector[82u8, 12u8, 38u8, 49u8, 6u8, 145u8, 99u8, 109u8, 31u8, 187u8, 222u8, 12u8, 75u8, 29u8, 137u8, 83u8, 65u8, 82u8, 88u8, 202u8, 173u8, 63u8, 159u8, 13u8, 5u8, 1u8, 250u8, 37u8, 8u8, 236u8, 85u8, 40u8, 0u8, 225u8, 245u8, 5u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8]; // Wrong public inputs
        
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
        let vk_bytes = vector[216u8, 245u8, 57u8, 226u8, 236u8, 255u8, 165u8, 135u8, 13u8, 186u8, 23u8, 109u8, 106u8, 154u8, 133u8, 145u8, 245u8, 93u8, 94u8, 225u8, 181u8, 90u8, 234u8, 59u8, 52u8, 124u8, 81u8, 152u8, 194u8, 162u8, 37u8, 153u8, 62u8, 92u8, 40u8, 97u8, 7u8, 199u8, 184u8, 147u8, 130u8, 8u8, 32u8, 79u8, 253u8, 35u8, 45u8, 252u8, 202u8, 152u8, 113u8, 67u8, 191u8, 30u8, 186u8, 101u8, 22u8, 162u8, 169u8, 53u8, 201u8, 186u8, 111u8, 47u8, 231u8, 251u8, 17u8, 179u8, 57u8, 43u8, 177u8, 195u8, 232u8, 188u8, 52u8, 48u8, 10u8, 197u8, 183u8, 204u8, 164u8, 29u8, 75u8, 164u8, 199u8, 177u8, 27u8, 178u8, 98u8, 179u8, 108u8, 113u8, 112u8, 64u8, 185u8, 31u8, 224u8, 67u8, 33u8, 161u8, 35u8, 32u8, 64u8, 139u8, 104u8, 128u8, 164u8, 91u8, 193u8, 28u8, 146u8, 102u8, 221u8, 44u8, 102u8, 34u8, 188u8, 136u8, 137u8, 77u8, 235u8, 224u8, 255u8, 5u8, 185u8, 227u8, 242u8, 40u8, 136u8, 105u8, 207u8, 236u8, 106u8, 197u8, 149u8, 20u8, 198u8, 165u8, 212u8, 254u8, 231u8, 187u8, 220u8, 165u8, 19u8, 241u8, 198u8, 205u8, 111u8, 197u8, 85u8, 128u8, 60u8, 53u8, 240u8, 154u8, 152u8, 28u8, 113u8, 172u8, 238u8, 239u8, 201u8, 225u8, 60u8, 50u8, 9u8, 111u8, 119u8, 251u8, 89u8, 147u8, 81u8, 172u8, 140u8, 117u8, 166u8, 194u8, 11u8, 84u8, 178u8, 143u8, 51u8, 57u8, 57u8, 121u8, 254u8, 34u8, 244u8, 204u8, 80u8, 37u8, 219u8, 120u8, 129u8, 4u8, 207u8, 71u8, 104u8, 208u8, 250u8, 28u8, 177u8, 136u8, 158u8, 171u8, 24u8, 70u8, 248u8, 157u8, 28u8, 210u8, 3u8, 72u8, 133u8, 9u8, 10u8, 120u8, 232u8, 138u8, 141u8, 99u8, 154u8, 25u8, 3u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 132u8, 64u8, 99u8, 228u8, 137u8, 95u8, 230u8, 102u8, 53u8, 58u8, 83u8, 14u8, 216u8, 63u8, 107u8, 18u8, 32u8, 117u8, 170u8, 76u8, 146u8, 206u8, 115u8, 75u8, 155u8, 163u8, 203u8, 102u8, 83u8, 125u8, 243u8, 145u8, 94u8, 242u8, 230u8, 35u8, 5u8, 49u8, 109u8, 124u8, 244u8, 12u8, 206u8, 231u8, 161u8, 146u8, 22u8, 47u8, 71u8, 77u8, 75u8, 249u8, 48u8, 100u8, 159u8, 168u8, 221u8, 54u8, 39u8, 188u8, 61u8, 30u8, 126u8, 19u8, 196u8, 133u8, 24u8, 232u8, 111u8, 172u8, 33u8, 184u8, 231u8, 211u8, 175u8, 179u8, 254u8, 68u8, 5u8, 206u8, 93u8, 113u8, 139u8, 205u8, 36u8, 62u8, 21u8, 250u8, 145u8, 150u8, 55u8, 139u8, 152u8, 181u8, 45u8, 137u8];
        
        let ctx = test_scenario::ctx(&mut scenario);
        proximity::init_verifying_key(&server_cap, vk_bytes, ctx);
        
        test_scenario::return_to_sender(&scenario, server_cap);
    };

    // Create commitment with different coordinates
    scenario.next_tx(@0x1);
    {
        let server_cap = test_scenario::take_from_sender<proximity::ServerCap>(&scenario);
        let commitment_bytes = vector[138u8, 65u8, 13u8, 107u8, 180u8, 206u8, 214u8, 86u8, 67u8, 170u8, 145u8, 247u8, 108u8, 56u8, 101u8, 85u8, 107u8, 71u8, 196u8, 255u8, 136u8, 95u8, 81u8, 210u8, 101u8, 4u8, 225u8, 161u8, 133u8, 77u8, 87u8, 37u8]; // Different Poseidon commitment hash (32 bytes)
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
        let proof_bytes = vector[166u8, 68u8, 149u8, 223u8, 195u8, 136u8, 20u8, 207u8, 214u8, 17u8, 203u8, 243u8, 85u8, 237u8, 18u8, 235u8, 144u8, 241u8, 95u8, 202u8, 148u8, 108u8, 22u8, 151u8, 149u8, 151u8, 117u8, 106u8, 38u8, 222u8, 133u8, 32u8, 20u8, 207u8, 96u8, 46u8, 145u8, 205u8, 33u8, 187u8, 193u8, 210u8, 97u8, 74u8, 59u8, 145u8, 149u8, 72u8, 118u8, 81u8, 174u8, 55u8, 189u8, 84u8, 100u8, 195u8, 229u8, 56u8, 1u8, 184u8, 240u8, 223u8, 89u8, 13u8, 91u8, 162u8, 192u8, 91u8, 33u8, 185u8, 133u8, 227u8, 254u8, 3u8, 27u8, 224u8, 134u8, 79u8, 119u8, 215u8, 212u8, 26u8, 104u8, 95u8, 255u8, 226u8, 27u8, 85u8, 113u8, 50u8, 208u8, 211u8, 74u8, 70u8, 185u8, 156u8, 19u8, 116u8, 130u8, 100u8, 197u8, 40u8, 177u8, 102u8, 65u8, 122u8, 205u8, 169u8, 175u8, 232u8, 95u8, 138u8, 46u8, 8u8, 87u8, 125u8, 134u8, 200u8, 93u8, 183u8, 201u8, 254u8, 234u8, 205u8, 134u8, 93u8, 159u8, 163u8];
        let public_inputs = vector[138u8, 65u8, 13u8, 107u8, 180u8, 206u8, 214u8, 86u8, 67u8, 170u8, 145u8, 247u8, 108u8, 56u8, 101u8, 85u8, 107u8, 71u8, 196u8, 255u8, 136u8, 95u8, 81u8, 210u8, 101u8, 4u8, 225u8, 161u8, 133u8, 77u8, 87u8, 37u8, 0u8, 225u8, 245u8, 5u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8];
        
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
        let vk_bytes = vector[216u8, 245u8, 57u8, 226u8, 236u8, 255u8, 165u8, 135u8, 13u8, 186u8, 23u8, 109u8, 106u8, 154u8, 133u8, 145u8, 245u8, 93u8, 94u8, 225u8, 181u8, 90u8, 234u8, 59u8, 52u8, 124u8, 81u8, 152u8, 194u8, 162u8, 37u8, 153u8, 62u8, 92u8, 40u8, 97u8, 7u8, 199u8, 184u8, 147u8, 130u8, 8u8, 32u8, 79u8, 253u8, 35u8, 45u8, 252u8, 202u8, 152u8, 113u8, 67u8, 191u8, 30u8, 186u8, 101u8, 22u8, 162u8, 169u8, 53u8, 201u8, 186u8, 111u8, 47u8, 231u8, 251u8, 17u8, 179u8, 57u8, 43u8, 177u8, 195u8, 232u8, 188u8, 52u8, 48u8, 10u8, 197u8, 183u8, 204u8, 164u8, 29u8, 75u8, 164u8, 199u8, 177u8, 27u8, 178u8, 98u8, 179u8, 108u8, 113u8, 112u8, 64u8, 185u8, 31u8, 224u8, 67u8, 33u8, 161u8, 35u8, 32u8, 64u8, 139u8, 104u8, 128u8, 164u8, 91u8, 193u8, 28u8, 146u8, 102u8, 221u8, 44u8, 102u8, 34u8, 188u8, 136u8, 137u8, 77u8, 235u8, 224u8, 255u8, 5u8, 185u8, 227u8, 242u8, 40u8, 136u8, 105u8, 207u8, 236u8, 106u8, 197u8, 149u8, 20u8, 198u8, 165u8, 212u8, 254u8, 231u8, 187u8, 220u8, 165u8, 19u8, 241u8, 198u8, 205u8, 111u8, 197u8, 85u8, 128u8, 60u8, 53u8, 240u8, 154u8, 152u8, 28u8, 113u8, 172u8, 238u8, 239u8, 201u8, 225u8, 60u8, 50u8, 9u8, 111u8, 119u8, 251u8, 89u8, 147u8, 81u8, 172u8, 140u8, 117u8, 166u8, 194u8, 11u8, 84u8, 178u8, 143u8, 51u8, 57u8, 57u8, 121u8, 254u8, 34u8, 244u8, 204u8, 80u8, 37u8, 219u8, 120u8, 129u8, 4u8, 207u8, 71u8, 104u8, 208u8, 250u8, 28u8, 177u8, 136u8, 158u8, 171u8, 24u8, 70u8, 248u8, 157u8, 28u8, 210u8, 3u8, 72u8, 133u8, 9u8, 10u8, 120u8, 232u8, 138u8, 141u8, 99u8, 154u8, 25u8, 3u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 132u8, 64u8, 99u8, 228u8, 137u8, 95u8, 230u8, 102u8, 53u8, 58u8, 83u8, 14u8, 216u8, 63u8, 107u8, 18u8, 32u8, 117u8, 170u8, 76u8, 146u8, 206u8, 115u8, 75u8, 155u8, 163u8, 203u8, 102u8, 83u8, 125u8, 243u8, 145u8, 94u8, 242u8, 230u8, 35u8, 5u8, 49u8, 109u8, 124u8, 244u8, 12u8, 206u8, 231u8, 161u8, 146u8, 22u8, 47u8, 71u8, 77u8, 75u8, 249u8, 48u8, 100u8, 159u8, 168u8, 221u8, 54u8, 39u8, 188u8, 61u8, 30u8, 126u8, 19u8, 196u8, 133u8, 24u8, 232u8, 111u8, 172u8, 33u8, 184u8, 231u8, 211u8, 175u8, 179u8, 254u8, 68u8, 5u8, 206u8, 93u8, 113u8, 139u8, 205u8, 36u8, 62u8, 21u8, 250u8, 145u8, 150u8, 55u8, 139u8, 152u8, 181u8, 45u8, 137u8];
        
        let ctx = test_scenario::ctx(&mut scenario);
        proximity::init_verifying_key(&server_cap, vk_bytes, ctx);
        
        test_scenario::return_to_sender(&scenario, server_cap);
    };

    // Create commitment with absolute value coordinates
    scenario.next_tx(@0x1);
    {
        let server_cap = test_scenario::take_from_sender<proximity::ServerCap>(&scenario);
        let commitment_bytes = vector[154u8, 230u8, 17u8, 155u8, 12u8, 34u8, 132u8, 52u8, 112u8, 107u8, 194u8, 225u8, 231u8, 8u8, 181u8, 255u8, 148u8, 184u8, 57u8, 244u8, 239u8, 252u8, 87u8, 214u8, 70u8, 135u8, 39u8, 0u8, 179u8, 54u8, 250u8, 35u8]; // Absolute value Poseidon commitment hash (32 bytes)
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
        let proof_bytes = vector[119u8, 217u8, 83u8, 26u8, 73u8, 134u8, 225u8, 176u8, 185u8, 117u8, 80u8, 55u8, 85u8, 126u8, 20u8, 70u8, 9u8, 140u8, 158u8, 35u8, 7u8, 174u8, 107u8, 29u8, 231u8, 249u8, 243u8, 19u8, 230u8, 235u8, 75u8, 44u8, 168u8, 43u8, 77u8, 195u8, 195u8, 166u8, 28u8, 234u8, 204u8, 33u8, 208u8, 37u8, 242u8, 224u8, 90u8, 43u8, 61u8, 179u8, 112u8, 238u8, 233u8, 165u8, 135u8, 199u8, 208u8, 158u8, 253u8, 19u8, 105u8, 208u8, 190u8, 20u8, 31u8, 195u8, 186u8, 207u8, 62u8, 114u8, 188u8, 20u8, 155u8, 14u8, 218u8, 38u8, 77u8, 207u8, 69u8, 41u8, 147u8, 213u8, 218u8, 92u8, 137u8, 133u8, 137u8, 83u8, 189u8, 83u8, 199u8, 74u8, 150u8, 161u8, 28u8, 135u8, 199u8, 161u8, 212u8, 64u8, 32u8, 212u8, 253u8, 251u8, 60u8, 110u8, 70u8, 90u8, 132u8, 163u8, 54u8, 194u8, 12u8, 220u8, 227u8, 35u8, 76u8, 250u8, 218u8, 207u8, 135u8, 174u8, 6u8, 98u8, 148u8, 165u8, 127u8, 21u8];
        let public_inputs = vector[154u8, 230u8, 17u8, 155u8, 12u8, 34u8, 132u8, 52u8, 112u8, 107u8, 194u8, 225u8, 231u8, 8u8, 181u8, 255u8, 148u8, 184u8, 57u8, 244u8, 239u8, 252u8, 87u8, 214u8, 70u8, 135u8, 39u8, 0u8, 179u8, 54u8, 250u8, 35u8, 0u8, 225u8, 245u8, 5u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8];
        
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
        let vk_bytes = vector[216u8, 245u8, 57u8, 226u8, 236u8, 255u8, 165u8, 135u8, 13u8, 186u8, 23u8, 109u8, 106u8, 154u8, 133u8, 145u8, 245u8, 93u8, 94u8, 225u8, 181u8, 90u8, 234u8, 59u8, 52u8, 124u8, 81u8, 152u8, 194u8, 162u8, 37u8, 153u8, 62u8, 92u8, 40u8, 97u8, 7u8, 199u8, 184u8, 147u8, 130u8, 8u8, 32u8, 79u8, 253u8, 35u8, 45u8, 252u8, 202u8, 152u8, 113u8, 67u8, 191u8, 30u8, 186u8, 101u8, 22u8, 162u8, 169u8, 53u8, 201u8, 186u8, 111u8, 47u8, 231u8, 251u8, 17u8, 179u8, 57u8, 43u8, 177u8, 195u8, 232u8, 188u8, 52u8, 48u8, 10u8, 197u8, 183u8, 204u8, 164u8, 29u8, 75u8, 164u8, 199u8, 177u8, 27u8, 178u8, 98u8, 179u8, 108u8, 113u8, 112u8, 64u8, 185u8, 31u8, 224u8, 67u8, 33u8, 161u8, 35u8, 32u8, 64u8, 139u8, 104u8, 128u8, 164u8, 91u8, 193u8, 28u8, 146u8, 102u8, 221u8, 44u8, 102u8, 34u8, 188u8, 136u8, 137u8, 77u8, 235u8, 224u8, 255u8, 5u8, 185u8, 227u8, 242u8, 40u8, 136u8, 105u8, 207u8, 236u8, 106u8, 197u8, 149u8, 20u8, 198u8, 165u8, 212u8, 254u8, 231u8, 187u8, 220u8, 165u8, 19u8, 241u8, 198u8, 205u8, 111u8, 197u8, 85u8, 128u8, 60u8, 53u8, 240u8, 154u8, 152u8, 28u8, 113u8, 172u8, 238u8, 239u8, 201u8, 225u8, 60u8, 50u8, 9u8, 111u8, 119u8, 251u8, 89u8, 147u8, 81u8, 172u8, 140u8, 117u8, 166u8, 194u8, 11u8, 84u8, 178u8, 143u8, 51u8, 57u8, 57u8, 121u8, 254u8, 34u8, 244u8, 204u8, 80u8, 37u8, 219u8, 120u8, 129u8, 4u8, 207u8, 71u8, 104u8, 208u8, 250u8, 28u8, 177u8, 136u8, 158u8, 171u8, 24u8, 70u8, 248u8, 157u8, 28u8, 210u8, 3u8, 72u8, 133u8, 9u8, 10u8, 120u8, 232u8, 138u8, 141u8, 99u8, 154u8, 25u8, 3u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 132u8, 64u8, 99u8, 228u8, 137u8, 95u8, 230u8, 102u8, 53u8, 58u8, 83u8, 14u8, 216u8, 63u8, 107u8, 18u8, 32u8, 117u8, 170u8, 76u8, 146u8, 206u8, 115u8, 75u8, 155u8, 163u8, 203u8, 102u8, 83u8, 125u8, 243u8, 145u8, 94u8, 242u8, 230u8, 35u8, 5u8, 49u8, 109u8, 124u8, 244u8, 12u8, 206u8, 231u8, 161u8, 146u8, 22u8, 47u8, 71u8, 77u8, 75u8, 249u8, 48u8, 100u8, 159u8, 168u8, 221u8, 54u8, 39u8, 188u8, 61u8, 30u8, 126u8, 19u8, 196u8, 133u8, 24u8, 232u8, 111u8, 172u8, 33u8, 184u8, 231u8, 211u8, 175u8, 179u8, 254u8, 68u8, 5u8, 206u8, 93u8, 113u8, 139u8, 205u8, 36u8, 62u8, 21u8, 250u8, 145u8, 150u8, 55u8, 139u8, 152u8, 181u8, 45u8, 137u8];
        
        let ctx = test_scenario::ctx(&mut scenario);
        proximity::init_verifying_key(&server_cap, vk_bytes, ctx);
        
        test_scenario::return_to_sender(&scenario, server_cap);
    };

    // Create commitment with SSU_B hash
    scenario.next_tx(@0x1);
    {
        let server_cap = test_scenario::take_from_sender<proximity::ServerCap>(&scenario);
        let commitment_b_bytes = vector[138u8, 65u8, 13u8, 107u8, 180u8, 206u8, 214u8, 86u8, 67u8, 170u8, 145u8, 247u8, 108u8, 56u8, 101u8, 85u8, 107u8, 71u8, 196u8, 255u8, 136u8, 95u8, 81u8, 210u8, 101u8, 4u8, 225u8, 161u8, 133u8, 77u8, 87u8, 37u8]; // SSU_B commitment hash
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
        
        let proof_for_ssu_a = vector[172u8, 16u8, 129u8, 220u8, 153u8, 129u8, 134u8, 240u8, 37u8, 42u8, 226u8, 254u8, 89u8, 5u8, 213u8, 101u8, 96u8, 86u8, 251u8, 147u8, 208u8, 230u8, 109u8, 185u8, 162u8, 25u8, 240u8, 227u8, 162u8, 89u8, 137u8, 164u8, 177u8, 33u8, 7u8, 250u8, 80u8, 124u8, 65u8, 68u8, 7u8, 62u8, 47u8, 248u8, 2u8, 244u8, 223u8, 51u8, 229u8, 35u8, 166u8, 57u8, 106u8, 48u8, 136u8, 148u8, 158u8, 41u8, 107u8, 190u8, 186u8, 254u8, 100u8, 44u8, 77u8, 31u8, 93u8, 197u8, 179u8, 85u8, 207u8, 195u8, 226u8, 164u8, 114u8, 124u8, 216u8, 20u8, 101u8, 201u8, 137u8, 8u8, 21u8, 223u8, 17u8, 179u8, 74u8, 211u8, 173u8, 194u8, 199u8, 125u8, 72u8, 150u8, 136u8, 134u8, 113u8, 113u8, 197u8, 34u8, 222u8, 178u8, 198u8, 4u8, 58u8, 210u8, 94u8, 107u8, 0u8, 68u8, 156u8, 143u8, 165u8, 156u8, 151u8, 134u8, 166u8, 115u8, 178u8, 206u8, 210u8, 231u8, 112u8, 183u8, 229u8, 79u8, 21u8, 33u8]; // Valid proof for SSU_A
        let public_inputs_for_ssu_a = vector[82u8, 12u8, 38u8, 49u8, 6u8, 145u8, 99u8, 109u8, 31u8, 187u8, 222u8, 12u8, 75u8, 29u8, 137u8, 83u8, 190u8, 82u8, 88u8, 202u8, 173u8, 63u8, 159u8, 13u8, 5u8, 1u8, 250u8, 37u8, 8u8, 236u8, 85u8, 40u8, 0u8, 225u8, 245u8, 5u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8]; // Public inputs containing SSU_A's hash (WRONG!)
        
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
        let vk_bytes = vector[216u8, 245u8, 57u8, 226u8, 236u8, 255u8, 165u8, 135u8, 13u8, 186u8, 23u8, 109u8, 106u8, 154u8, 133u8, 145u8, 245u8, 93u8, 94u8, 225u8, 181u8, 90u8, 234u8, 59u8, 52u8, 124u8, 81u8, 152u8, 194u8, 162u8, 37u8, 153u8, 62u8, 92u8, 40u8, 97u8, 7u8, 199u8, 184u8, 147u8, 130u8, 8u8, 32u8, 79u8, 253u8, 35u8, 45u8, 252u8, 202u8, 152u8, 113u8, 67u8, 191u8, 30u8, 186u8, 101u8, 22u8, 162u8, 169u8, 53u8, 201u8, 186u8, 111u8, 47u8, 231u8, 251u8, 17u8, 179u8, 57u8, 43u8, 177u8, 195u8, 232u8, 188u8, 52u8, 48u8, 10u8, 197u8, 183u8, 204u8, 164u8, 29u8, 75u8, 164u8, 199u8, 177u8, 27u8, 178u8, 98u8, 179u8, 108u8, 113u8, 112u8, 64u8, 185u8, 31u8, 224u8, 67u8, 33u8, 161u8, 35u8, 32u8, 64u8, 139u8, 104u8, 128u8, 164u8, 91u8, 193u8, 28u8, 146u8, 102u8, 221u8, 44u8, 102u8, 34u8, 188u8, 136u8, 137u8, 77u8, 235u8, 224u8, 255u8, 5u8, 185u8, 227u8, 242u8, 40u8, 136u8, 105u8, 207u8, 236u8, 106u8, 197u8, 149u8, 20u8, 198u8, 165u8, 212u8, 254u8, 231u8, 187u8, 220u8, 165u8, 19u8, 241u8, 198u8, 205u8, 111u8, 197u8, 85u8, 128u8, 60u8, 53u8, 240u8, 154u8, 152u8, 28u8, 113u8, 172u8, 238u8, 239u8, 201u8, 225u8, 60u8, 50u8, 9u8, 111u8, 119u8, 251u8, 89u8, 147u8, 81u8, 172u8, 140u8, 117u8, 166u8, 194u8, 11u8, 84u8, 178u8, 143u8, 51u8, 57u8, 57u8, 121u8, 254u8, 34u8, 244u8, 204u8, 80u8, 37u8, 219u8, 120u8, 129u8, 4u8, 207u8, 71u8, 104u8, 208u8, 250u8, 28u8, 177u8, 136u8, 158u8, 171u8, 24u8, 70u8, 248u8, 157u8, 28u8, 210u8, 3u8, 72u8, 133u8, 9u8, 10u8, 120u8, 232u8, 138u8, 141u8, 99u8, 154u8, 25u8, 3u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 132u8, 64u8, 99u8, 228u8, 137u8, 95u8, 230u8, 102u8, 53u8, 58u8, 83u8, 14u8, 216u8, 63u8, 107u8, 18u8, 32u8, 117u8, 170u8, 76u8, 146u8, 206u8, 115u8, 75u8, 155u8, 163u8, 203u8, 102u8, 83u8, 125u8, 243u8, 145u8, 94u8, 242u8, 230u8, 35u8, 5u8, 49u8, 109u8, 124u8, 244u8, 12u8, 206u8, 231u8, 161u8, 146u8, 22u8, 47u8, 71u8, 77u8, 75u8, 249u8, 48u8, 100u8, 159u8, 168u8, 221u8, 54u8, 39u8, 188u8, 61u8, 30u8, 126u8, 19u8, 196u8, 133u8, 24u8, 232u8, 111u8, 172u8, 33u8, 184u8, 231u8, 211u8, 175u8, 179u8, 254u8, 68u8, 5u8, 206u8, 93u8, 113u8, 139u8, 205u8, 36u8, 62u8, 21u8, 250u8, 145u8, 150u8, 55u8, 139u8, 152u8, 181u8, 45u8, 137u8];
        
        let ctx = test_scenario::ctx(&mut scenario);
        proximity::init_verifying_key(&server_cap, vk_bytes, ctx);
        
        test_scenario::return_to_sender(&scenario, server_cap);
    };

    // Create commitment with SSU_A hash
    scenario.next_tx(@0x1);
    {
        let server_cap = test_scenario::take_from_sender<proximity::ServerCap>(&scenario);
        let commitment_bytes = vector[82u8, 12u8, 38u8, 49u8, 6u8, 145u8, 99u8, 109u8, 31u8, 187u8, 222u8, 12u8, 75u8, 29u8, 137u8, 83u8, 190u8, 82u8, 88u8, 202u8, 173u8, 63u8, 159u8, 13u8, 5u8, 1u8, 250u8, 37u8, 8u8, 236u8, 85u8, 40u8]; // SSU_A commitment hash
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
        let proof_bytes = vector[172u8, 16u8, 129u8, 220u8, 153u8, 129u8, 134u8, 240u8, 37u8, 42u8, 226u8, 254u8, 89u8, 5u8, 213u8, 101u8, 96u8, 86u8, 251u8, 147u8, 208u8, 230u8, 109u8, 185u8, 162u8, 25u8, 240u8, 227u8, 162u8, 89u8, 137u8, 164u8, 177u8, 33u8, 7u8, 250u8, 80u8, 124u8, 65u8, 68u8, 7u8, 62u8, 47u8, 248u8, 2u8, 244u8, 223u8, 51u8, 229u8, 35u8, 166u8, 57u8, 106u8, 48u8, 136u8, 148u8, 158u8, 41u8, 107u8, 190u8, 186u8, 254u8, 100u8, 44u8, 77u8, 31u8, 93u8, 197u8, 179u8, 85u8, 207u8, 195u8, 226u8, 164u8, 114u8, 124u8, 216u8, 20u8, 101u8, 201u8, 137u8, 8u8, 21u8, 223u8, 17u8, 179u8, 74u8, 211u8, 173u8, 194u8, 199u8, 125u8, 72u8, 150u8, 136u8, 134u8, 113u8, 113u8, 197u8, 34u8, 222u8, 178u8, 198u8, 4u8, 58u8, 210u8, 94u8, 107u8, 0u8, 68u8, 156u8, 143u8, 165u8, 156u8, 151u8, 134u8, 166u8, 115u8, 178u8, 206u8, 210u8, 231u8, 112u8, 183u8, 229u8, 79u8, 21u8, 33u8]; // Valid proof for SSU_A
        let public_inputs = vector[82u8, 12u8, 38u8, 49u8, 6u8, 145u8, 99u8, 109u8, 31u8, 187u8, 222u8, 12u8, 75u8, 29u8, 137u8, 83u8, 190u8, 82u8, 88u8, 202u8, 173u8, 63u8, 159u8, 13u8, 5u8, 1u8, 250u8, 37u8, 8u8, 236u8, 85u8, 40u8, 0u8, 225u8, 245u8, 5u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8]; // Public inputs with SSU_A hash (CORRECT!)
        
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
