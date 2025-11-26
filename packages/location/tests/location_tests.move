
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
        let vk_bytes = vector[159u8, 125u8, 116u8, 221u8, 211u8, 94u8, 104u8, 232u8, 249u8, 187u8, 94u8, 26u8, 99u8, 198u8, 180u8, 25u8, 140u8, 50u8, 78u8, 158u8, 79u8, 65u8, 120u8, 87u8, 117u8, 227u8, 37u8, 92u8, 165u8, 41u8, 111u8, 2u8, 95u8, 77u8, 220u8, 30u8, 227u8, 157u8, 16u8, 118u8, 65u8, 154u8, 70u8, 216u8, 32u8, 19u8, 160u8, 44u8, 126u8, 69u8, 56u8, 25u8, 162u8, 177u8, 115u8, 209u8, 4u8, 32u8, 188u8, 116u8, 106u8, 4u8, 185u8, 42u8, 202u8, 203u8, 232u8, 68u8, 183u8, 130u8, 236u8, 21u8, 66u8, 67u8, 114u8, 194u8, 127u8, 190u8, 47u8, 221u8, 121u8, 94u8, 56u8, 233u8, 60u8, 61u8, 238u8, 56u8, 112u8, 217u8, 204u8, 37u8, 243u8, 16u8, 116u8, 43u8, 252u8, 254u8, 242u8, 13u8, 197u8, 10u8, 146u8, 12u8, 5u8, 122u8, 114u8, 86u8, 119u8, 142u8, 119u8, 63u8, 206u8, 211u8, 194u8, 140u8, 239u8, 34u8, 45u8, 39u8, 87u8, 174u8, 46u8, 247u8, 46u8, 13u8, 149u8, 23u8, 247u8, 195u8, 181u8, 147u8, 223u8, 29u8, 254u8, 64u8, 123u8, 74u8, 7u8, 16u8, 185u8, 194u8, 159u8, 203u8, 176u8, 115u8, 123u8, 143u8, 128u8, 201u8, 2u8, 165u8, 123u8, 201u8, 173u8, 155u8, 124u8, 254u8, 225u8, 16u8, 173u8, 153u8, 156u8, 59u8, 127u8, 15u8, 153u8, 219u8, 89u8, 251u8, 236u8, 113u8, 158u8, 213u8, 62u8, 159u8, 41u8, 173u8, 136u8, 62u8, 72u8, 211u8, 15u8, 251u8, 42u8, 22u8, 150u8, 221u8, 114u8, 178u8, 36u8, 31u8, 79u8, 200u8, 184u8, 64u8, 106u8, 44u8, 238u8, 251u8, 122u8, 161u8, 175u8, 85u8, 243u8, 180u8, 171u8, 7u8, 121u8, 40u8, 49u8, 41u8, 220u8, 167u8, 168u8, 100u8, 96u8, 6u8, 189u8, 95u8, 81u8, 21u8, 185u8, 158u8, 3u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 109u8, 115u8, 103u8, 155u8, 106u8, 108u8, 193u8, 67u8, 1u8, 4u8, 189u8, 136u8, 118u8, 213u8, 174u8, 122u8, 43u8, 19u8, 158u8, 183u8, 29u8, 238u8, 9u8, 168u8, 72u8, 205u8, 42u8, 234u8, 47u8, 140u8, 158u8, 165u8, 37u8, 81u8, 41u8, 252u8, 135u8, 106u8, 135u8, 90u8, 197u8, 158u8, 218u8, 118u8, 192u8, 241u8, 54u8, 81u8, 198u8, 203u8, 149u8, 29u8, 136u8, 125u8, 129u8, 235u8, 10u8, 37u8, 29u8, 116u8, 64u8, 9u8, 174u8, 136u8, 20u8, 184u8, 61u8, 119u8, 146u8, 62u8, 141u8, 32u8, 111u8, 243u8, 165u8, 102u8, 111u8, 161u8, 109u8, 209u8, 26u8, 249u8, 35u8, 249u8, 152u8, 140u8, 3u8, 150u8, 104u8, 136u8, 54u8, 183u8, 196u8, 130u8, 7u8, 37u8]; // Canonical verifying key (328 bytes)
        
        let ctx = test_scenario::ctx(&mut scenario);
        proximity::init_verifying_key(&server_cap, vk_bytes, ctx);
        
        test_scenario::return_to_sender(&scenario, server_cap);
    };

    // Create commitment (Poseidon hash - 32 bytes)
    scenario.next_tx(@0x1);
    {
        let server_cap = test_scenario::take_from_sender<proximity::ServerCap>(&scenario);
        let commitment_bytes = vector[211u8, 191u8, 157u8, 38u8, 148u8, 23u8, 14u8, 203u8, 117u8, 81u8, 203u8, 250u8, 202u8, 202u8, 120u8, 143u8, 149u8, 48u8, 213u8, 99u8, 117u8, 8u8, 163u8, 237u8, 207u8, 221u8, 146u8, 79u8, 175u8, 173u8, 128u8, 6u8]; // Poseidon hash (32 bytes)
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
        let proof_bytes = vector[221u8, 109u8, 192u8, 158u8, 149u8, 62u8, 169u8, 141u8, 229u8, 69u8, 91u8, 102u8, 152u8, 223u8, 182u8, 172u8, 208u8, 114u8, 164u8, 151u8, 243u8, 96u8, 180u8, 52u8, 150u8, 247u8, 39u8, 205u8, 59u8, 178u8, 92u8, 170u8, 59u8, 47u8, 158u8, 138u8, 52u8, 70u8, 17u8, 9u8, 119u8, 94u8, 132u8, 194u8, 11u8, 224u8, 50u8, 13u8, 49u8, 17u8, 229u8, 101u8, 232u8, 76u8, 94u8, 255u8, 227u8, 56u8, 22u8, 152u8, 57u8, 70u8, 210u8, 22u8, 188u8, 16u8, 8u8, 129u8, 71u8, 7u8, 253u8, 110u8, 176u8, 181u8, 173u8, 215u8, 55u8, 155u8, 41u8, 205u8, 251u8, 199u8, 190u8, 214u8, 113u8, 141u8, 118u8, 240u8, 100u8, 2u8, 13u8, 46u8, 80u8, 19u8, 165u8, 162u8, 246u8, 83u8, 162u8, 87u8, 109u8, 84u8, 53u8, 110u8, 132u8, 254u8, 142u8, 253u8, 232u8, 217u8, 187u8, 70u8, 248u8, 163u8, 38u8, 247u8, 140u8, 184u8, 8u8, 108u8, 119u8, 38u8, 113u8, 233u8, 81u8, 252u8, 247u8, 148u8];
        let public_inputs = vector[211u8, 191u8, 157u8, 38u8, 148u8, 23u8, 14u8, 203u8, 117u8, 81u8, 203u8, 250u8, 202u8, 202u8, 120u8, 143u8, 149u8, 48u8, 213u8, 99u8, 117u8, 8u8, 163u8, 237u8, 207u8, 221u8, 146u8, 79u8, 175u8, 173u8, 128u8, 6u8, 0u8, 225u8, 245u8, 5u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8]; // [commitment_hash, max_distance_squared] (64 bytes total)
        
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
        let vk_bytes = vector[159u8, 125u8, 116u8, 221u8, 211u8, 94u8, 104u8, 232u8, 249u8, 187u8, 94u8, 26u8, 99u8, 198u8, 180u8, 25u8, 140u8, 50u8, 78u8, 158u8, 79u8, 65u8, 120u8, 87u8, 117u8, 227u8, 37u8, 92u8, 165u8, 41u8, 111u8, 2u8, 95u8, 77u8, 220u8, 30u8, 227u8, 157u8, 16u8, 118u8, 65u8, 154u8, 70u8, 216u8, 32u8, 19u8, 160u8, 44u8, 126u8, 69u8, 56u8, 25u8, 162u8, 177u8, 115u8, 209u8, 4u8, 32u8, 188u8, 116u8, 106u8, 4u8, 185u8, 42u8, 202u8, 203u8, 232u8, 68u8, 183u8, 130u8, 236u8, 21u8, 66u8, 67u8, 114u8, 194u8, 127u8, 190u8, 47u8, 221u8, 121u8, 94u8, 56u8, 233u8, 60u8, 61u8, 238u8, 56u8, 112u8, 217u8, 204u8, 37u8, 243u8, 16u8, 116u8, 43u8, 252u8, 254u8, 242u8, 13u8, 197u8, 10u8, 146u8, 12u8, 5u8, 122u8, 114u8, 86u8, 119u8, 142u8, 119u8, 63u8, 206u8, 211u8, 194u8, 140u8, 239u8, 34u8, 45u8, 39u8, 87u8, 174u8, 46u8, 247u8, 46u8, 13u8, 149u8, 23u8, 247u8, 195u8, 181u8, 147u8, 223u8, 29u8, 254u8, 64u8, 123u8, 74u8, 7u8, 16u8, 185u8, 194u8, 159u8, 203u8, 176u8, 115u8, 123u8, 143u8, 128u8, 201u8, 2u8, 165u8, 123u8, 201u8, 173u8, 155u8, 124u8, 254u8, 225u8, 16u8, 173u8, 153u8, 156u8, 59u8, 127u8, 15u8, 153u8, 219u8, 89u8, 251u8, 236u8, 113u8, 158u8, 213u8, 62u8, 159u8, 41u8, 173u8, 136u8, 62u8, 72u8, 211u8, 15u8, 251u8, 42u8, 22u8, 150u8, 221u8, 114u8, 178u8, 36u8, 31u8, 79u8, 200u8, 184u8, 64u8, 106u8, 44u8, 238u8, 251u8, 122u8, 161u8, 175u8, 85u8, 243u8, 180u8, 171u8, 7u8, 121u8, 40u8, 49u8, 41u8, 220u8, 167u8, 168u8, 100u8, 96u8, 6u8, 189u8, 95u8, 81u8, 21u8, 185u8, 158u8, 3u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 109u8, 115u8, 103u8, 155u8, 106u8, 108u8, 193u8, 67u8, 1u8, 4u8, 189u8, 136u8, 118u8, 213u8, 174u8, 122u8, 43u8, 19u8, 158u8, 183u8, 29u8, 238u8, 9u8, 168u8, 72u8, 205u8, 42u8, 234u8, 47u8, 140u8, 158u8, 165u8, 37u8, 81u8, 41u8, 252u8, 135u8, 106u8, 135u8, 90u8, 197u8, 158u8, 218u8, 118u8, 192u8, 241u8, 54u8, 81u8, 198u8, 203u8, 149u8, 29u8, 136u8, 125u8, 129u8, 235u8, 10u8, 37u8, 29u8, 116u8, 64u8, 9u8, 174u8, 136u8, 20u8, 184u8, 61u8, 119u8, 146u8, 62u8, 141u8, 32u8, 111u8, 243u8, 165u8, 102u8, 111u8, 161u8, 109u8, 209u8, 26u8, 249u8, 35u8, 249u8, 152u8, 140u8, 3u8, 150u8, 104u8, 136u8, 54u8, 183u8, 196u8, 130u8, 7u8, 37u8];
        
        let ctx = test_scenario::ctx(&mut scenario);
        proximity::init_verifying_key(&server_cap, vk_bytes, ctx);
        
        test_scenario::return_to_sender(&scenario, server_cap);
    };

    // Create commitment
    scenario.next_tx(@0x1);
    {
        let server_cap = test_scenario::take_from_sender<proximity::ServerCap>(&scenario);
        let commitment_bytes = vector[211u8, 191u8, 157u8, 38u8, 148u8, 23u8, 14u8, 203u8, 117u8, 81u8, 203u8, 250u8, 202u8, 202u8, 120u8, 143u8, 149u8, 48u8, 213u8, 99u8, 117u8, 8u8, 163u8, 237u8, 207u8, 221u8, 146u8, 79u8, 175u8, 173u8, 128u8, 6u8];
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
        let proof_bytes = vector[221u8, 109u8, 192u8, 158u8, 149u8, 62u8, 169u8, 141u8, 229u8, 69u8, 164u8, 102u8, 152u8, 223u8, 182u8, 172u8, 208u8, 114u8, 164u8, 151u8, 243u8, 96u8, 180u8, 52u8, 150u8, 247u8, 39u8, 205u8, 59u8, 178u8, 92u8, 170u8, 59u8, 47u8, 158u8, 138u8, 52u8, 70u8, 17u8, 9u8, 119u8, 94u8, 132u8, 194u8, 11u8, 224u8, 50u8, 13u8, 49u8, 17u8, 229u8, 101u8, 232u8, 76u8, 94u8, 255u8, 227u8, 56u8, 22u8, 152u8, 57u8, 70u8, 210u8, 22u8, 188u8, 16u8, 8u8, 129u8, 71u8, 7u8, 253u8, 110u8, 176u8, 181u8, 173u8, 215u8, 55u8, 155u8, 41u8, 205u8, 251u8, 199u8, 190u8, 214u8, 113u8, 141u8, 118u8, 240u8, 100u8, 2u8, 13u8, 46u8, 80u8, 19u8, 165u8, 162u8, 246u8, 83u8, 162u8, 87u8, 109u8, 84u8, 53u8, 110u8, 132u8, 254u8, 142u8, 253u8, 232u8, 217u8, 187u8, 70u8, 248u8, 163u8, 38u8, 247u8, 140u8, 184u8, 8u8, 108u8, 119u8, 38u8, 113u8, 233u8, 81u8, 252u8, 247u8, 148u8]; // Corrupted proof bytes
        let public_inputs = vector[211u8, 191u8, 157u8, 38u8, 148u8, 23u8, 14u8, 203u8, 117u8, 81u8, 203u8, 250u8, 202u8, 202u8, 120u8, 143u8, 149u8, 48u8, 213u8, 99u8, 117u8, 8u8, 163u8, 237u8, 207u8, 221u8, 146u8, 79u8, 175u8, 173u8, 128u8, 6u8, 0u8, 225u8, 245u8, 5u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8];
        
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
        let wrong_vk_bytes = vector[0u8, 29u8, 119u8, 6u8, 233u8, 64u8, 236u8, 77u8, 106u8, 138u8, 152u8, 226u8, 209u8, 86u8, 20u8, 242u8, 81u8, 144u8, 129u8, 110u8, 232u8, 35u8, 223u8, 60u8, 73u8, 70u8, 51u8, 150u8, 131u8, 144u8, 70u8, 131u8, 126u8, 102u8, 10u8, 7u8, 246u8, 37u8, 175u8, 15u8, 188u8, 183u8, 78u8, 123u8, 155u8, 186u8, 152u8, 28u8, 171u8, 79u8, 177u8, 217u8, 16u8, 57u8, 98u8, 184u8, 150u8, 158u8, 154u8, 37u8, 77u8, 196u8, 5u8, 24u8, 91u8, 177u8, 244u8, 51u8, 53u8, 95u8, 193u8, 185u8, 29u8, 204u8, 178u8, 148u8, 235u8, 239u8, 67u8, 114u8, 193u8, 118u8, 87u8, 132u8, 206u8, 172u8, 202u8, 151u8, 97u8, 95u8, 128u8, 105u8, 73u8, 157u8, 188u8, 31u8, 173u8, 147u8, 73u8, 43u8, 103u8, 79u8, 100u8, 165u8, 99u8, 233u8, 215u8, 121u8, 133u8, 225u8, 236u8, 106u8, 99u8, 201u8, 248u8, 152u8, 177u8, 51u8, 194u8, 122u8, 17u8, 7u8, 62u8, 254u8, 175u8, 185u8, 228u8, 4u8, 235u8, 110u8, 138u8, 23u8, 114u8, 140u8, 197u8, 232u8, 50u8, 193u8, 109u8, 66u8, 65u8, 124u8, 241u8, 114u8, 162u8, 64u8, 211u8, 111u8, 185u8, 220u8, 217u8, 220u8, 183u8, 47u8, 186u8, 12u8, 206u8, 228u8, 212u8, 141u8, 119u8, 225u8, 105u8, 71u8, 188u8, 232u8, 30u8, 49u8, 178u8, 224u8, 254u8, 70u8, 48u8, 98u8, 238u8, 63u8, 203u8, 211u8, 43u8, 105u8, 142u8, 242u8, 144u8, 248u8, 242u8, 93u8, 227u8, 72u8, 10u8, 181u8, 44u8, 21u8, 91u8, 3u8, 47u8, 7u8, 183u8, 98u8, 140u8, 243u8, 5u8, 93u8, 76u8, 66u8, 201u8, 21u8, 255u8, 118u8, 248u8, 244u8, 149u8, 6u8, 144u8, 20u8, 138u8, 51u8, 78u8, 153u8, 29u8, 109u8, 78u8, 70u8, 234u8, 163u8, 3u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 196u8, 11u8, 8u8, 184u8, 223u8, 151u8, 111u8, 159u8, 60u8, 52u8, 219u8, 156u8, 254u8, 222u8, 236u8, 41u8, 152u8, 52u8, 109u8, 135u8, 207u8, 248u8, 255u8, 105u8, 221u8, 212u8, 209u8, 137u8, 62u8, 250u8, 39u8, 156u8, 107u8, 65u8, 86u8, 127u8, 173u8, 214u8, 223u8, 35u8, 21u8, 213u8, 168u8, 248u8, 73u8, 243u8, 148u8, 100u8, 103u8, 253u8, 32u8, 80u8, 226u8, 67u8, 121u8, 189u8, 100u8, 47u8, 112u8, 184u8, 251u8, 51u8, 152u8, 11u8, 184u8, 236u8, 56u8, 5u8, 63u8, 45u8, 53u8, 122u8, 192u8, 79u8, 135u8, 131u8, 210u8, 128u8, 101u8, 42u8, 209u8, 111u8, 72u8, 115u8, 141u8, 225u8, 155u8, 191u8, 105u8, 7u8, 192u8, 252u8, 65u8, 197u8, 255u8, 21u8]; // Wrong VK bytes (from different trusted setup)
        
        let ctx = test_scenario::ctx(&mut scenario);
        proximity::init_verifying_key(&server_cap, wrong_vk_bytes, ctx);
        
        test_scenario::return_to_sender(&scenario, server_cap);
    };

    // Create commitment
    scenario.next_tx(@0x1);
    {
        let server_cap = test_scenario::take_from_sender<proximity::ServerCap>(&scenario);
        let commitment_bytes = vector[211u8, 191u8, 157u8, 38u8, 148u8, 23u8, 14u8, 203u8, 117u8, 81u8, 203u8, 250u8, 202u8, 202u8, 120u8, 143u8, 149u8, 48u8, 213u8, 99u8, 117u8, 8u8, 163u8, 237u8, 207u8, 221u8, 146u8, 79u8, 175u8, 173u8, 128u8, 6u8];
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
        let proof_bytes = vector[221u8, 109u8, 192u8, 158u8, 149u8, 62u8, 169u8, 141u8, 229u8, 69u8, 91u8, 102u8, 152u8, 223u8, 182u8, 172u8, 208u8, 114u8, 164u8, 151u8, 243u8, 96u8, 180u8, 52u8, 150u8, 247u8, 39u8, 205u8, 59u8, 178u8, 92u8, 170u8, 59u8, 47u8, 158u8, 138u8, 52u8, 70u8, 17u8, 9u8, 119u8, 94u8, 132u8, 194u8, 11u8, 224u8, 50u8, 13u8, 49u8, 17u8, 229u8, 101u8, 232u8, 76u8, 94u8, 255u8, 227u8, 56u8, 22u8, 152u8, 57u8, 70u8, 210u8, 22u8, 188u8, 16u8, 8u8, 129u8, 71u8, 7u8, 253u8, 110u8, 176u8, 181u8, 173u8, 215u8, 55u8, 155u8, 41u8, 205u8, 251u8, 199u8, 190u8, 214u8, 113u8, 141u8, 118u8, 240u8, 100u8, 2u8, 13u8, 46u8, 80u8, 19u8, 165u8, 162u8, 246u8, 83u8, 162u8, 87u8, 109u8, 84u8, 53u8, 110u8, 132u8, 254u8, 142u8, 253u8, 232u8, 217u8, 187u8, 70u8, 248u8, 163u8, 38u8, 247u8, 140u8, 184u8, 8u8, 108u8, 119u8, 38u8, 113u8, 233u8, 81u8, 252u8, 247u8, 148u8]; // Proof generated with correct VK
        let public_inputs = vector[211u8, 191u8, 157u8, 38u8, 148u8, 23u8, 14u8, 203u8, 117u8, 81u8, 203u8, 250u8, 202u8, 202u8, 120u8, 143u8, 149u8, 48u8, 213u8, 99u8, 117u8, 8u8, 163u8, 237u8, 207u8, 221u8, 146u8, 79u8, 175u8, 173u8, 128u8, 6u8, 0u8, 225u8, 245u8, 5u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8];
        
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
        let vk_bytes = vector[159u8, 125u8, 116u8, 221u8, 211u8, 94u8, 104u8, 232u8, 249u8, 187u8, 94u8, 26u8, 99u8, 198u8, 180u8, 25u8, 140u8, 50u8, 78u8, 158u8, 79u8, 65u8, 120u8, 87u8, 117u8, 227u8, 37u8, 92u8, 165u8, 41u8, 111u8, 2u8, 95u8, 77u8, 220u8, 30u8, 227u8, 157u8, 16u8, 118u8, 65u8, 154u8, 70u8, 216u8, 32u8, 19u8, 160u8, 44u8, 126u8, 69u8, 56u8, 25u8, 162u8, 177u8, 115u8, 209u8, 4u8, 32u8, 188u8, 116u8, 106u8, 4u8, 185u8, 42u8, 202u8, 203u8, 232u8, 68u8, 183u8, 130u8, 236u8, 21u8, 66u8, 67u8, 114u8, 194u8, 127u8, 190u8, 47u8, 221u8, 121u8, 94u8, 56u8, 233u8, 60u8, 61u8, 238u8, 56u8, 112u8, 217u8, 204u8, 37u8, 243u8, 16u8, 116u8, 43u8, 252u8, 254u8, 242u8, 13u8, 197u8, 10u8, 146u8, 12u8, 5u8, 122u8, 114u8, 86u8, 119u8, 142u8, 119u8, 63u8, 206u8, 211u8, 194u8, 140u8, 239u8, 34u8, 45u8, 39u8, 87u8, 174u8, 46u8, 247u8, 46u8, 13u8, 149u8, 23u8, 247u8, 195u8, 181u8, 147u8, 223u8, 29u8, 254u8, 64u8, 123u8, 74u8, 7u8, 16u8, 185u8, 194u8, 159u8, 203u8, 176u8, 115u8, 123u8, 143u8, 128u8, 201u8, 2u8, 165u8, 123u8, 201u8, 173u8, 155u8, 124u8, 254u8, 225u8, 16u8, 173u8, 153u8, 156u8, 59u8, 127u8, 15u8, 153u8, 219u8, 89u8, 251u8, 236u8, 113u8, 158u8, 213u8, 62u8, 159u8, 41u8, 173u8, 136u8, 62u8, 72u8, 211u8, 15u8, 251u8, 42u8, 22u8, 150u8, 221u8, 114u8, 178u8, 36u8, 31u8, 79u8, 200u8, 184u8, 64u8, 106u8, 44u8, 238u8, 251u8, 122u8, 161u8, 175u8, 85u8, 243u8, 180u8, 171u8, 7u8, 121u8, 40u8, 49u8, 41u8, 220u8, 167u8, 168u8, 100u8, 96u8, 6u8, 189u8, 95u8, 81u8, 21u8, 185u8, 158u8, 3u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 109u8, 115u8, 103u8, 155u8, 106u8, 108u8, 193u8, 67u8, 1u8, 4u8, 189u8, 136u8, 118u8, 213u8, 174u8, 122u8, 43u8, 19u8, 158u8, 183u8, 29u8, 238u8, 9u8, 168u8, 72u8, 205u8, 42u8, 234u8, 47u8, 140u8, 158u8, 165u8, 37u8, 81u8, 41u8, 252u8, 135u8, 106u8, 135u8, 90u8, 197u8, 158u8, 218u8, 118u8, 192u8, 241u8, 54u8, 81u8, 198u8, 203u8, 149u8, 29u8, 136u8, 125u8, 129u8, 235u8, 10u8, 37u8, 29u8, 116u8, 64u8, 9u8, 174u8, 136u8, 20u8, 184u8, 61u8, 119u8, 146u8, 62u8, 141u8, 32u8, 111u8, 243u8, 165u8, 102u8, 111u8, 161u8, 109u8, 209u8, 26u8, 249u8, 35u8, 249u8, 152u8, 140u8, 3u8, 150u8, 104u8, 136u8, 54u8, 183u8, 196u8, 130u8, 7u8, 37u8];
        
        let ctx = test_scenario::ctx(&mut scenario);
        proximity::init_verifying_key(&server_cap, vk_bytes, ctx);
        
        test_scenario::return_to_sender(&scenario, server_cap);
    };

    // Create commitment
    scenario.next_tx(@0x1);
    {
        let server_cap = test_scenario::take_from_sender<proximity::ServerCap>(&scenario);
        let commitment_bytes = vector[211u8, 191u8, 157u8, 38u8, 148u8, 23u8, 14u8, 203u8, 117u8, 81u8, 203u8, 250u8, 202u8, 202u8, 120u8, 143u8, 149u8, 48u8, 213u8, 99u8, 117u8, 8u8, 163u8, 237u8, 207u8, 221u8, 146u8, 79u8, 175u8, 173u8, 128u8, 6u8];
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
        let proof_bytes = vector[221u8, 109u8, 192u8, 158u8, 149u8, 62u8, 169u8, 141u8, 229u8, 69u8, 91u8, 102u8, 152u8, 223u8, 182u8, 172u8, 208u8, 114u8, 164u8, 151u8, 243u8, 96u8, 180u8, 52u8, 150u8, 247u8, 39u8, 205u8, 59u8, 178u8, 92u8, 170u8, 59u8, 47u8, 158u8, 138u8, 52u8, 70u8, 17u8, 9u8, 119u8, 94u8, 132u8, 194u8, 11u8, 224u8, 50u8, 13u8, 49u8, 17u8, 229u8, 101u8, 232u8, 76u8, 94u8, 255u8, 227u8, 56u8, 22u8, 152u8, 57u8, 70u8, 210u8, 22u8, 188u8, 16u8, 8u8, 129u8, 71u8, 7u8, 253u8, 110u8, 176u8, 181u8, 173u8, 215u8, 55u8, 155u8, 41u8, 205u8, 251u8, 199u8, 190u8, 214u8, 113u8, 141u8, 118u8, 240u8, 100u8, 2u8, 13u8, 46u8, 80u8, 19u8, 165u8, 162u8, 246u8, 83u8, 162u8, 87u8, 109u8, 84u8, 53u8, 110u8, 132u8, 254u8, 142u8, 253u8, 232u8, 217u8, 187u8, 70u8, 248u8, 163u8, 38u8, 247u8, 140u8, 184u8, 8u8, 108u8, 119u8, 38u8, 113u8, 233u8, 81u8, 252u8, 247u8, 148u8];
        let public_inputs = vector[211u8, 191u8, 157u8, 38u8, 148u8, 23u8, 14u8, 203u8, 117u8, 81u8, 203u8, 250u8, 202u8, 202u8, 120u8, 143u8, 106u8, 48u8, 213u8, 99u8, 117u8, 8u8, 163u8, 237u8, 207u8, 221u8, 146u8, 79u8, 175u8, 173u8, 128u8, 6u8, 0u8, 225u8, 245u8, 5u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8]; // Wrong public inputs
        
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
        let vk_bytes = vector[159u8, 125u8, 116u8, 221u8, 211u8, 94u8, 104u8, 232u8, 249u8, 187u8, 94u8, 26u8, 99u8, 198u8, 180u8, 25u8, 140u8, 50u8, 78u8, 158u8, 79u8, 65u8, 120u8, 87u8, 117u8, 227u8, 37u8, 92u8, 165u8, 41u8, 111u8, 2u8, 95u8, 77u8, 220u8, 30u8, 227u8, 157u8, 16u8, 118u8, 65u8, 154u8, 70u8, 216u8, 32u8, 19u8, 160u8, 44u8, 126u8, 69u8, 56u8, 25u8, 162u8, 177u8, 115u8, 209u8, 4u8, 32u8, 188u8, 116u8, 106u8, 4u8, 185u8, 42u8, 202u8, 203u8, 232u8, 68u8, 183u8, 130u8, 236u8, 21u8, 66u8, 67u8, 114u8, 194u8, 127u8, 190u8, 47u8, 221u8, 121u8, 94u8, 56u8, 233u8, 60u8, 61u8, 238u8, 56u8, 112u8, 217u8, 204u8, 37u8, 243u8, 16u8, 116u8, 43u8, 252u8, 254u8, 242u8, 13u8, 197u8, 10u8, 146u8, 12u8, 5u8, 122u8, 114u8, 86u8, 119u8, 142u8, 119u8, 63u8, 206u8, 211u8, 194u8, 140u8, 239u8, 34u8, 45u8, 39u8, 87u8, 174u8, 46u8, 247u8, 46u8, 13u8, 149u8, 23u8, 247u8, 195u8, 181u8, 147u8, 223u8, 29u8, 254u8, 64u8, 123u8, 74u8, 7u8, 16u8, 185u8, 194u8, 159u8, 203u8, 176u8, 115u8, 123u8, 143u8, 128u8, 201u8, 2u8, 165u8, 123u8, 201u8, 173u8, 155u8, 124u8, 254u8, 225u8, 16u8, 173u8, 153u8, 156u8, 59u8, 127u8, 15u8, 153u8, 219u8, 89u8, 251u8, 236u8, 113u8, 158u8, 213u8, 62u8, 159u8, 41u8, 173u8, 136u8, 62u8, 72u8, 211u8, 15u8, 251u8, 42u8, 22u8, 150u8, 221u8, 114u8, 178u8, 36u8, 31u8, 79u8, 200u8, 184u8, 64u8, 106u8, 44u8, 238u8, 251u8, 122u8, 161u8, 175u8, 85u8, 243u8, 180u8, 171u8, 7u8, 121u8, 40u8, 49u8, 41u8, 220u8, 167u8, 168u8, 100u8, 96u8, 6u8, 189u8, 95u8, 81u8, 21u8, 185u8, 158u8, 3u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 109u8, 115u8, 103u8, 155u8, 106u8, 108u8, 193u8, 67u8, 1u8, 4u8, 189u8, 136u8, 118u8, 213u8, 174u8, 122u8, 43u8, 19u8, 158u8, 183u8, 29u8, 238u8, 9u8, 168u8, 72u8, 205u8, 42u8, 234u8, 47u8, 140u8, 158u8, 165u8, 37u8, 81u8, 41u8, 252u8, 135u8, 106u8, 135u8, 90u8, 197u8, 158u8, 218u8, 118u8, 192u8, 241u8, 54u8, 81u8, 198u8, 203u8, 149u8, 29u8, 136u8, 125u8, 129u8, 235u8, 10u8, 37u8, 29u8, 116u8, 64u8, 9u8, 174u8, 136u8, 20u8, 184u8, 61u8, 119u8, 146u8, 62u8, 141u8, 32u8, 111u8, 243u8, 165u8, 102u8, 111u8, 161u8, 109u8, 209u8, 26u8, 249u8, 35u8, 249u8, 152u8, 140u8, 3u8, 150u8, 104u8, 136u8, 54u8, 183u8, 196u8, 130u8, 7u8, 37u8];
        
        let ctx = test_scenario::ctx(&mut scenario);
        proximity::init_verifying_key(&server_cap, vk_bytes, ctx);
        
        test_scenario::return_to_sender(&scenario, server_cap);
    };

    // Create commitment with different coordinates
    scenario.next_tx(@0x1);
    {
        let server_cap = test_scenario::take_from_sender<proximity::ServerCap>(&scenario);
        let commitment_bytes = vector[190u8, 255u8, 109u8, 255u8, 178u8, 214u8, 43u8, 126u8, 111u8, 94u8, 232u8, 188u8, 111u8, 47u8, 96u8, 214u8, 249u8, 74u8, 42u8, 92u8, 27u8, 189u8, 172u8, 145u8, 105u8, 236u8, 142u8, 123u8, 23u8, 21u8, 189u8, 33u8]; // Different Poseidon commitment hash (32 bytes)
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
        let proof_bytes = vector[163u8, 212u8, 54u8, 248u8, 96u8, 87u8, 153u8, 94u8, 131u8, 100u8, 53u8, 7u8, 208u8, 178u8, 194u8, 78u8, 107u8, 136u8, 247u8, 31u8, 203u8, 140u8, 182u8, 171u8, 146u8, 233u8, 72u8, 203u8, 42u8, 204u8, 17u8, 34u8, 74u8, 241u8, 71u8, 44u8, 175u8, 122u8, 166u8, 170u8, 96u8, 162u8, 66u8, 21u8, 126u8, 158u8, 29u8, 251u8, 156u8, 40u8, 154u8, 154u8, 164u8, 219u8, 17u8, 120u8, 54u8, 7u8, 202u8, 34u8, 107u8, 193u8, 130u8, 16u8, 45u8, 12u8, 196u8, 69u8, 239u8, 201u8, 94u8, 246u8, 112u8, 180u8, 155u8, 53u8, 50u8, 181u8, 42u8, 94u8, 125u8, 128u8, 145u8, 138u8, 174u8, 212u8, 219u8, 208u8, 104u8, 79u8, 3u8, 132u8, 105u8, 134u8, 7u8, 21u8, 211u8, 18u8, 180u8, 4u8, 171u8, 212u8, 176u8, 154u8, 224u8, 222u8, 210u8, 127u8, 61u8, 221u8, 76u8, 150u8, 96u8, 170u8, 158u8, 194u8, 139u8, 174u8, 54u8, 210u8, 211u8, 32u8, 171u8, 26u8, 126u8, 208u8, 196u8, 132u8];
        let public_inputs = vector[190u8, 255u8, 109u8, 255u8, 178u8, 214u8, 43u8, 126u8, 111u8, 94u8, 232u8, 188u8, 111u8, 47u8, 96u8, 214u8, 249u8, 74u8, 42u8, 92u8, 27u8, 189u8, 172u8, 145u8, 105u8, 236u8, 142u8, 123u8, 23u8, 21u8, 189u8, 33u8, 0u8, 225u8, 245u8, 5u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8];
        
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
        let vk_bytes = vector[159u8, 125u8, 116u8, 221u8, 211u8, 94u8, 104u8, 232u8, 249u8, 187u8, 94u8, 26u8, 99u8, 198u8, 180u8, 25u8, 140u8, 50u8, 78u8, 158u8, 79u8, 65u8, 120u8, 87u8, 117u8, 227u8, 37u8, 92u8, 165u8, 41u8, 111u8, 2u8, 95u8, 77u8, 220u8, 30u8, 227u8, 157u8, 16u8, 118u8, 65u8, 154u8, 70u8, 216u8, 32u8, 19u8, 160u8, 44u8, 126u8, 69u8, 56u8, 25u8, 162u8, 177u8, 115u8, 209u8, 4u8, 32u8, 188u8, 116u8, 106u8, 4u8, 185u8, 42u8, 202u8, 203u8, 232u8, 68u8, 183u8, 130u8, 236u8, 21u8, 66u8, 67u8, 114u8, 194u8, 127u8, 190u8, 47u8, 221u8, 121u8, 94u8, 56u8, 233u8, 60u8, 61u8, 238u8, 56u8, 112u8, 217u8, 204u8, 37u8, 243u8, 16u8, 116u8, 43u8, 252u8, 254u8, 242u8, 13u8, 197u8, 10u8, 146u8, 12u8, 5u8, 122u8, 114u8, 86u8, 119u8, 142u8, 119u8, 63u8, 206u8, 211u8, 194u8, 140u8, 239u8, 34u8, 45u8, 39u8, 87u8, 174u8, 46u8, 247u8, 46u8, 13u8, 149u8, 23u8, 247u8, 195u8, 181u8, 147u8, 223u8, 29u8, 254u8, 64u8, 123u8, 74u8, 7u8, 16u8, 185u8, 194u8, 159u8, 203u8, 176u8, 115u8, 123u8, 143u8, 128u8, 201u8, 2u8, 165u8, 123u8, 201u8, 173u8, 155u8, 124u8, 254u8, 225u8, 16u8, 173u8, 153u8, 156u8, 59u8, 127u8, 15u8, 153u8, 219u8, 89u8, 251u8, 236u8, 113u8, 158u8, 213u8, 62u8, 159u8, 41u8, 173u8, 136u8, 62u8, 72u8, 211u8, 15u8, 251u8, 42u8, 22u8, 150u8, 221u8, 114u8, 178u8, 36u8, 31u8, 79u8, 200u8, 184u8, 64u8, 106u8, 44u8, 238u8, 251u8, 122u8, 161u8, 175u8, 85u8, 243u8, 180u8, 171u8, 7u8, 121u8, 40u8, 49u8, 41u8, 220u8, 167u8, 168u8, 100u8, 96u8, 6u8, 189u8, 95u8, 81u8, 21u8, 185u8, 158u8, 3u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 109u8, 115u8, 103u8, 155u8, 106u8, 108u8, 193u8, 67u8, 1u8, 4u8, 189u8, 136u8, 118u8, 213u8, 174u8, 122u8, 43u8, 19u8, 158u8, 183u8, 29u8, 238u8, 9u8, 168u8, 72u8, 205u8, 42u8, 234u8, 47u8, 140u8, 158u8, 165u8, 37u8, 81u8, 41u8, 252u8, 135u8, 106u8, 135u8, 90u8, 197u8, 158u8, 218u8, 118u8, 192u8, 241u8, 54u8, 81u8, 198u8, 203u8, 149u8, 29u8, 136u8, 125u8, 129u8, 235u8, 10u8, 37u8, 29u8, 116u8, 64u8, 9u8, 174u8, 136u8, 20u8, 184u8, 61u8, 119u8, 146u8, 62u8, 141u8, 32u8, 111u8, 243u8, 165u8, 102u8, 111u8, 161u8, 109u8, 209u8, 26u8, 249u8, 35u8, 249u8, 152u8, 140u8, 3u8, 150u8, 104u8, 136u8, 54u8, 183u8, 196u8, 130u8, 7u8, 37u8];
        
        let ctx = test_scenario::ctx(&mut scenario);
        proximity::init_verifying_key(&server_cap, vk_bytes, ctx);
        
        test_scenario::return_to_sender(&scenario, server_cap);
    };

    // Create commitment with absolute value coordinates
    scenario.next_tx(@0x1);
    {
        let server_cap = test_scenario::take_from_sender<proximity::ServerCap>(&scenario);
        let commitment_bytes = vector[100u8, 128u8, 131u8, 157u8, 149u8, 115u8, 168u8, 254u8, 113u8, 236u8, 1u8, 15u8, 185u8, 57u8, 184u8, 195u8, 155u8, 87u8, 134u8, 126u8, 85u8, 138u8, 105u8, 142u8, 242u8, 181u8, 255u8, 191u8, 85u8, 216u8, 119u8, 1u8]; // Absolute value Poseidon commitment hash (32 bytes)
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
        let proof_bytes = vector[221u8, 109u8, 192u8, 158u8, 149u8, 62u8, 169u8, 141u8, 229u8, 69u8, 91u8, 102u8, 152u8, 223u8, 182u8, 172u8, 208u8, 114u8, 164u8, 151u8, 243u8, 96u8, 180u8, 52u8, 150u8, 247u8, 39u8, 205u8, 59u8, 178u8, 92u8, 170u8, 59u8, 47u8, 158u8, 138u8, 52u8, 70u8, 17u8, 9u8, 119u8, 94u8, 132u8, 194u8, 11u8, 224u8, 50u8, 13u8, 49u8, 17u8, 229u8, 101u8, 232u8, 76u8, 94u8, 255u8, 227u8, 56u8, 22u8, 152u8, 57u8, 70u8, 210u8, 22u8, 188u8, 16u8, 8u8, 129u8, 71u8, 7u8, 253u8, 110u8, 176u8, 181u8, 173u8, 215u8, 55u8, 155u8, 41u8, 205u8, 251u8, 199u8, 190u8, 214u8, 113u8, 141u8, 118u8, 240u8, 100u8, 2u8, 13u8, 46u8, 80u8, 19u8, 165u8, 162u8, 246u8, 83u8, 162u8, 87u8, 109u8, 84u8, 53u8, 110u8, 132u8, 254u8, 142u8, 253u8, 232u8, 217u8, 187u8, 70u8, 248u8, 163u8, 38u8, 247u8, 140u8, 184u8, 8u8, 108u8, 119u8, 38u8, 113u8, 233u8, 81u8, 252u8, 247u8, 148u8];
        let public_inputs = vector[211u8, 191u8, 157u8, 38u8, 148u8, 23u8, 14u8, 203u8, 117u8, 81u8, 203u8, 250u8, 202u8, 202u8, 120u8, 143u8, 149u8, 48u8, 213u8, 99u8, 117u8, 8u8, 163u8, 237u8, 207u8, 221u8, 146u8, 79u8, 175u8, 173u8, 128u8, 6u8, 0u8, 225u8, 245u8, 5u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8];
        
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
