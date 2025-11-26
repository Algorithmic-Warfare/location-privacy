
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

    // Create commitment (Poseidon hash - 32 bytes)
    scenario.next_tx(@0x1);
    {
        let server_cap = test_scenario::take_from_sender<proximity::ServerCap>(&scenario);
        let commitment_bytes = vector[208u8, 241u8, 90u8, 28u8, 103u8, 15u8, 165u8, 81u8, 114u8, 249u8, 52u8, 22u8, 240u8, 197u8, 89u8, 215u8, 132u8, 185u8, 140u8, 252u8, 255u8, 186u8, 70u8, 12u8, 40u8, 215u8, 117u8, 37u8, 145u8, 192u8, 77u8, 9u8]; // Poseidon hash (32 bytes)
        let owner = @0x2;
        
        let ctx = test_scenario::ctx(&mut scenario);
        proximity::create_commitment(&server_cap, commitment_bytes, owner, ctx);
        
        test_scenario::return_to_sender(&scenario, server_cap);
    };

    // Verify proximity proof
    scenario.next_tx(@0x2);
    {
        let mut commitment = test_scenario::take_shared<proximity::LocationCommitment>(&scenario);
        let vk_bytes = vector[213u8, 160u8, 24u8, 127u8, 138u8, 1u8, 43u8, 90u8, 203u8, 76u8, 89u8, 116u8, 207u8, 63u8, 91u8, 129u8, 252u8, 251u8, 120u8, 195u8, 22u8, 5u8, 90u8, 100u8, 123u8, 8u8, 111u8, 246u8, 206u8, 137u8, 50u8, 39u8, 79u8, 35u8, 204u8, 118u8, 101u8, 50u8, 47u8, 52u8, 84u8, 43u8, 114u8, 168u8, 29u8, 158u8, 91u8, 46u8, 212u8, 194u8, 43u8, 145u8, 117u8, 216u8, 98u8, 128u8, 208u8, 45u8, 172u8, 137u8, 225u8, 46u8, 188u8, 38u8, 172u8, 179u8, 167u8, 0u8, 22u8, 9u8, 237u8, 33u8, 25u8, 148u8, 133u8, 144u8, 168u8, 128u8, 33u8, 171u8, 74u8, 117u8, 57u8, 25u8, 32u8, 155u8, 145u8, 212u8, 149u8, 229u8, 193u8, 247u8, 48u8, 235u8, 129u8, 44u8, 231u8, 169u8, 110u8, 212u8, 148u8, 35u8, 240u8, 35u8, 100u8, 60u8, 146u8, 26u8, 4u8, 231u8, 77u8, 153u8, 122u8, 172u8, 181u8, 50u8, 147u8, 17u8, 211u8, 42u8, 218u8, 79u8, 204u8, 168u8, 167u8, 13u8, 163u8, 38u8, 27u8, 121u8, 137u8, 161u8, 89u8, 207u8, 240u8, 171u8, 235u8, 120u8, 230u8, 102u8, 139u8, 81u8, 152u8, 123u8, 214u8, 238u8, 6u8, 195u8, 249u8, 77u8, 220u8, 67u8, 183u8, 119u8, 206u8, 98u8, 38u8, 167u8, 201u8, 135u8, 56u8, 165u8, 219u8, 184u8, 86u8, 197u8, 7u8, 114u8, 132u8, 16u8, 135u8, 239u8, 213u8, 131u8, 71u8, 188u8, 37u8, 112u8, 176u8, 20u8, 162u8, 12u8, 138u8, 221u8, 129u8, 221u8, 196u8, 10u8, 41u8, 102u8, 75u8, 3u8, 205u8, 86u8, 121u8, 60u8, 244u8, 245u8, 169u8, 184u8, 233u8, 148u8, 223u8, 80u8, 195u8, 155u8, 203u8, 18u8, 44u8, 159u8, 195u8, 50u8, 68u8, 235u8, 178u8, 158u8, 107u8, 91u8, 161u8, 228u8, 69u8, 7u8, 42u8, 165u8, 3u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 7u8, 54u8, 105u8, 92u8, 115u8, 48u8, 82u8, 67u8, 103u8, 158u8, 117u8, 10u8, 159u8, 255u8, 207u8, 242u8, 234u8, 78u8, 210u8, 176u8, 176u8, 42u8, 9u8, 12u8, 236u8, 220u8, 4u8, 180u8, 159u8, 69u8, 222u8, 13u8, 195u8, 94u8, 153u8, 121u8, 80u8, 125u8, 248u8, 176u8, 2u8, 152u8, 134u8, 72u8, 105u8, 187u8, 177u8, 55u8, 48u8, 138u8, 63u8, 23u8, 165u8, 181u8, 7u8, 242u8, 69u8, 238u8, 176u8, 217u8, 139u8, 8u8, 245u8, 16u8, 189u8, 221u8, 70u8, 86u8, 111u8, 172u8, 13u8, 136u8, 162u8, 97u8, 30u8, 137u8, 99u8, 10u8, 183u8, 30u8, 106u8, 181u8, 2u8, 65u8, 211u8, 63u8, 187u8, 243u8, 196u8, 126u8, 252u8, 4u8, 107u8, 196u8, 247u8, 153u8];
        let proof_bytes = vector[28u8, 214u8, 92u8, 71u8, 105u8, 102u8, 199u8, 206u8, 119u8, 146u8, 221u8, 184u8, 2u8, 112u8, 10u8, 139u8, 240u8, 146u8, 142u8, 233u8, 47u8, 9u8, 162u8, 9u8, 203u8, 132u8, 181u8, 119u8, 238u8, 111u8, 252u8, 166u8, 236u8, 23u8, 189u8, 227u8, 253u8, 151u8, 248u8, 11u8, 102u8, 163u8, 226u8, 225u8, 96u8, 97u8, 64u8, 225u8, 107u8, 102u8, 109u8, 165u8, 11u8, 84u8, 25u8, 118u8, 77u8, 244u8, 9u8, 1u8, 206u8, 201u8, 110u8, 19u8, 240u8, 97u8, 247u8, 148u8, 10u8, 250u8, 74u8, 51u8, 90u8, 243u8, 75u8, 174u8, 125u8, 50u8, 54u8, 117u8, 242u8, 208u8, 32u8, 103u8, 177u8, 246u8, 1u8, 43u8, 229u8, 27u8, 125u8, 79u8, 58u8, 83u8, 253u8, 155u8, 23u8, 231u8, 183u8, 118u8, 200u8, 45u8, 254u8, 177u8, 24u8, 229u8, 151u8, 84u8, 93u8, 191u8, 209u8, 247u8, 212u8, 69u8, 200u8, 194u8, 158u8, 52u8, 157u8, 126u8, 136u8, 182u8, 18u8, 249u8, 34u8, 112u8, 109u8, 8u8];
        let public_inputs = vector[208u8, 241u8, 90u8, 28u8, 103u8, 15u8, 165u8, 81u8, 114u8, 249u8, 52u8, 22u8, 240u8, 197u8, 89u8, 215u8, 132u8, 185u8, 140u8, 252u8, 255u8, 186u8, 70u8, 12u8, 40u8, 215u8, 117u8, 37u8, 145u8, 192u8, 77u8, 9u8, 0u8, 225u8, 245u8, 5u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8]; // [commitment_hash, max_distance_squared] (64 bytes total)
        
        let ctx = test_scenario::ctx(&mut scenario);
        proximity::verify_proximity_proof(&mut commitment, vk_bytes, proof_bytes, public_inputs, ctx);
        
        // Verify nonce was incremented
        let nonce = proximity::get_nonce(&commitment);
        assert!(nonce == 1, 0);
        
        test_scenario::return_shared(commitment);
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

    // Create commitment
    scenario.next_tx(@0x1);
    {
        let server_cap = test_scenario::take_from_sender<proximity::ServerCap>(&scenario);
        let commitment_bytes = vector[208u8, 241u8, 90u8, 28u8, 103u8, 15u8, 165u8, 81u8, 114u8, 249u8, 52u8, 22u8, 240u8, 197u8, 89u8, 215u8, 132u8, 185u8, 140u8, 252u8, 255u8, 186u8, 70u8, 12u8, 40u8, 215u8, 117u8, 37u8, 145u8, 192u8, 77u8, 9u8];
        let owner = @0x2;
        
        let ctx = test_scenario::ctx(&mut scenario);
        proximity::create_commitment(&server_cap, commitment_bytes, owner, ctx);
        
        test_scenario::return_to_sender(&scenario, server_cap);
    };

    // Try to verify with corrupted proof - should fail
    scenario.next_tx(@0x2);
    {
        let mut commitment = test_scenario::take_shared<proximity::LocationCommitment>(&scenario);
        let vk_bytes = vector[213u8, 160u8, 24u8, 127u8, 138u8, 1u8, 43u8, 90u8, 203u8, 76u8, 89u8, 116u8, 207u8, 63u8, 91u8, 129u8, 252u8, 251u8, 120u8, 195u8, 22u8, 5u8, 90u8, 100u8, 123u8, 8u8, 111u8, 246u8, 206u8, 137u8, 50u8, 39u8, 79u8, 35u8, 204u8, 118u8, 101u8, 50u8, 47u8, 52u8, 84u8, 43u8, 114u8, 168u8, 29u8, 158u8, 91u8, 46u8, 212u8, 194u8, 43u8, 145u8, 117u8, 216u8, 98u8, 128u8, 208u8, 45u8, 172u8, 137u8, 225u8, 46u8, 188u8, 38u8, 172u8, 179u8, 167u8, 0u8, 22u8, 9u8, 237u8, 33u8, 25u8, 148u8, 133u8, 144u8, 168u8, 128u8, 33u8, 171u8, 74u8, 117u8, 57u8, 25u8, 32u8, 155u8, 145u8, 212u8, 149u8, 229u8, 193u8, 247u8, 48u8, 235u8, 129u8, 44u8, 231u8, 169u8, 110u8, 212u8, 148u8, 35u8, 240u8, 35u8, 100u8, 60u8, 146u8, 26u8, 4u8, 231u8, 77u8, 153u8, 122u8, 172u8, 181u8, 50u8, 147u8, 17u8, 211u8, 42u8, 218u8, 79u8, 204u8, 168u8, 167u8, 13u8, 163u8, 38u8, 27u8, 121u8, 137u8, 161u8, 89u8, 207u8, 240u8, 171u8, 235u8, 120u8, 230u8, 102u8, 139u8, 81u8, 152u8, 123u8, 214u8, 238u8, 6u8, 195u8, 249u8, 77u8, 220u8, 67u8, 183u8, 119u8, 206u8, 98u8, 38u8, 167u8, 201u8, 135u8, 56u8, 165u8, 219u8, 184u8, 86u8, 197u8, 7u8, 114u8, 132u8, 16u8, 135u8, 239u8, 213u8, 131u8, 71u8, 188u8, 37u8, 112u8, 176u8, 20u8, 162u8, 12u8, 138u8, 221u8, 129u8, 221u8, 196u8, 10u8, 41u8, 102u8, 75u8, 3u8, 205u8, 86u8, 121u8, 60u8, 244u8, 245u8, 169u8, 184u8, 233u8, 148u8, 223u8, 80u8, 195u8, 155u8, 203u8, 18u8, 44u8, 159u8, 195u8, 50u8, 68u8, 235u8, 178u8, 158u8, 107u8, 91u8, 161u8, 228u8, 69u8, 7u8, 42u8, 165u8, 3u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 7u8, 54u8, 105u8, 92u8, 115u8, 48u8, 82u8, 67u8, 103u8, 158u8, 117u8, 10u8, 159u8, 255u8, 207u8, 242u8, 234u8, 78u8, 210u8, 176u8, 176u8, 42u8, 9u8, 12u8, 236u8, 220u8, 4u8, 180u8, 159u8, 69u8, 222u8, 13u8, 195u8, 94u8, 153u8, 121u8, 80u8, 125u8, 248u8, 176u8, 2u8, 152u8, 134u8, 72u8, 105u8, 187u8, 177u8, 55u8, 48u8, 138u8, 63u8, 23u8, 165u8, 181u8, 7u8, 242u8, 69u8, 238u8, 176u8, 217u8, 139u8, 8u8, 245u8, 16u8, 189u8, 221u8, 70u8, 86u8, 111u8, 172u8, 13u8, 136u8, 162u8, 97u8, 30u8, 137u8, 99u8, 10u8, 183u8, 30u8, 106u8, 181u8, 2u8, 65u8, 211u8, 63u8, 187u8, 243u8, 196u8, 126u8, 252u8, 4u8, 107u8, 196u8, 247u8, 153u8];
        let proof_bytes = vector[28u8, 214u8, 92u8, 71u8, 105u8, 102u8, 199u8, 206u8, 119u8, 146u8, 34u8, 184u8, 2u8, 112u8, 10u8, 139u8, 240u8, 146u8, 142u8, 233u8, 47u8, 9u8, 162u8, 9u8, 203u8, 132u8, 181u8, 119u8, 238u8, 111u8, 252u8, 166u8, 236u8, 23u8, 189u8, 227u8, 253u8, 151u8, 248u8, 11u8, 102u8, 163u8, 226u8, 225u8, 96u8, 97u8, 64u8, 225u8, 107u8, 102u8, 109u8, 165u8, 11u8, 84u8, 25u8, 118u8, 77u8, 244u8, 9u8, 1u8, 206u8, 201u8, 110u8, 19u8, 240u8, 97u8, 247u8, 148u8, 10u8, 250u8, 74u8, 51u8, 90u8, 243u8, 75u8, 174u8, 125u8, 50u8, 54u8, 117u8, 242u8, 208u8, 32u8, 103u8, 177u8, 246u8, 1u8, 43u8, 229u8, 27u8, 125u8, 79u8, 58u8, 83u8, 253u8, 155u8, 23u8, 231u8, 183u8, 118u8, 200u8, 45u8, 254u8, 177u8, 24u8, 229u8, 151u8, 84u8, 93u8, 191u8, 209u8, 247u8, 212u8, 69u8, 200u8, 194u8, 158u8, 52u8, 157u8, 126u8, 136u8, 182u8, 18u8, 249u8, 34u8, 112u8, 109u8, 8u8]; // Corrupted proof bytes
        let public_inputs = vector[208u8, 241u8, 90u8, 28u8, 103u8, 15u8, 165u8, 81u8, 114u8, 249u8, 52u8, 22u8, 240u8, 197u8, 89u8, 215u8, 132u8, 185u8, 140u8, 252u8, 255u8, 186u8, 70u8, 12u8, 40u8, 215u8, 117u8, 37u8, 145u8, 192u8, 77u8, 9u8, 0u8, 225u8, 245u8, 5u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8];
        
        let ctx = test_scenario::ctx(&mut scenario);
        // This should fail because the proof is corrupted
        proximity::verify_proximity_proof(&mut commitment, vk_bytes, proof_bytes, public_inputs, ctx);
        
        test_scenario::return_shared(commitment);
    };

    test_scenario::end(scenario);
}

#[test]
#[expected_failure]
fun test_wrong_verification_key_fails() {
    use sui::test_scenario;

    let mut scenario = test_scenario::begin(@0x1);
    {
        let ctx = test_scenario::ctx(&mut scenario);
        proximity::init_for_testing(ctx);
    };

    // Create commitment
    scenario.next_tx(@0x1);
    {
        let server_cap = test_scenario::take_from_sender<proximity::ServerCap>(&scenario);
        let commitment_bytes = vector[208u8, 241u8, 90u8, 28u8, 103u8, 15u8, 165u8, 81u8, 114u8, 249u8, 52u8, 22u8, 240u8, 197u8, 89u8, 215u8, 132u8, 185u8, 140u8, 252u8, 255u8, 186u8, 70u8, 12u8, 40u8, 215u8, 117u8, 37u8, 145u8, 192u8, 77u8, 9u8];
        let owner = @0x2;
        
        let ctx = test_scenario::ctx(&mut scenario);
        proximity::create_commitment(&server_cap, commitment_bytes, owner, ctx);
        
        test_scenario::return_to_sender(&scenario, server_cap);
    };

    // Try to verify with wrong verification key - should fail
    scenario.next_tx(@0x2);
    {
        let mut commitment = test_scenario::take_shared<proximity::LocationCommitment>(&scenario);
        let vk_bytes = vector[76u8, 229u8, 80u8, 159u8, 143u8, 90u8, 247u8, 206u8, 94u8, 190u8, 134u8, 39u8, 182u8, 24u8, 145u8, 157u8, 16u8, 143u8, 24u8, 214u8, 80u8, 235u8, 232u8, 149u8, 72u8, 211u8, 246u8, 229u8, 39u8, 165u8, 22u8, 26u8, 117u8, 217u8, 151u8, 70u8, 171u8, 173u8, 106u8, 150u8, 254u8, 231u8, 69u8, 161u8, 84u8, 233u8, 121u8, 252u8, 108u8, 109u8, 134u8, 24u8, 198u8, 241u8, 206u8, 239u8, 221u8, 134u8, 94u8, 88u8, 200u8, 56u8, 242u8, 19u8, 15u8, 241u8, 201u8, 187u8, 27u8, 61u8, 49u8, 151u8, 196u8, 94u8, 199u8, 165u8, 192u8, 72u8, 45u8, 120u8, 208u8, 94u8, 121u8, 250u8, 22u8, 100u8, 245u8, 43u8, 47u8, 137u8, 228u8, 114u8, 55u8, 45u8, 93u8, 24u8, 142u8, 99u8, 47u8, 150u8, 168u8, 204u8, 25u8, 235u8, 32u8, 65u8, 193u8, 185u8, 207u8, 163u8, 192u8, 202u8, 253u8, 174u8, 35u8, 227u8, 163u8, 99u8, 78u8, 85u8, 148u8, 134u8, 82u8, 103u8, 151u8, 51u8, 253u8, 45u8, 244u8, 212u8, 236u8, 195u8, 239u8, 25u8, 232u8, 133u8, 228u8, 142u8, 108u8, 147u8, 136u8, 171u8, 50u8, 216u8, 6u8, 124u8, 14u8, 123u8, 153u8, 77u8, 0u8, 238u8, 57u8, 145u8, 237u8, 142u8, 234u8, 150u8, 18u8, 136u8, 215u8, 5u8, 111u8, 5u8, 131u8, 34u8, 180u8, 202u8, 121u8, 183u8, 113u8, 3u8, 80u8, 215u8, 60u8, 73u8, 158u8, 101u8, 220u8, 59u8, 205u8, 91u8, 178u8, 161u8, 106u8, 139u8, 215u8, 123u8, 56u8, 187u8, 5u8, 31u8, 152u8, 15u8, 98u8, 146u8, 83u8, 180u8, 231u8, 182u8, 164u8, 180u8, 45u8, 135u8, 147u8, 209u8, 43u8, 174u8, 116u8, 8u8, 148u8, 117u8, 18u8, 84u8, 127u8, 90u8, 76u8, 244u8, 137u8, 147u8, 76u8, 120u8, 26u8, 138u8, 3u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 71u8, 6u8, 91u8, 225u8, 156u8, 143u8, 152u8, 106u8, 237u8, 16u8, 113u8, 245u8, 145u8, 158u8, 174u8, 51u8, 213u8, 167u8, 144u8, 7u8, 50u8, 213u8, 249u8, 207u8, 166u8, 219u8, 150u8, 10u8, 117u8, 70u8, 56u8, 130u8, 20u8, 35u8, 32u8, 250u8, 115u8, 243u8, 111u8, 232u8, 120u8, 68u8, 10u8, 247u8, 114u8, 251u8, 49u8, 58u8, 33u8, 118u8, 249u8, 216u8, 36u8, 202u8, 102u8, 205u8, 178u8, 55u8, 178u8, 225u8, 30u8, 182u8, 83u8, 138u8, 19u8, 94u8, 71u8, 36u8, 115u8, 134u8, 48u8, 182u8, 44u8, 28u8, 10u8, 9u8, 136u8, 21u8, 138u8, 163u8, 2u8, 93u8, 55u8, 13u8, 170u8, 26u8, 229u8, 114u8, 92u8, 196u8, 238u8, 35u8, 132u8, 217u8, 186u8, 20u8]; // Wrong VK bytes
        let proof_bytes = vector[28u8, 214u8, 92u8, 71u8, 105u8, 102u8, 199u8, 206u8, 119u8, 146u8, 221u8, 184u8, 2u8, 112u8, 10u8, 139u8, 240u8, 146u8, 142u8, 233u8, 47u8, 9u8, 162u8, 9u8, 203u8, 132u8, 181u8, 119u8, 238u8, 111u8, 252u8, 166u8, 236u8, 23u8, 189u8, 227u8, 253u8, 151u8, 248u8, 11u8, 102u8, 163u8, 226u8, 225u8, 96u8, 97u8, 64u8, 225u8, 107u8, 102u8, 109u8, 165u8, 11u8, 84u8, 25u8, 118u8, 77u8, 244u8, 9u8, 1u8, 206u8, 201u8, 110u8, 19u8, 240u8, 97u8, 247u8, 148u8, 10u8, 250u8, 74u8, 51u8, 90u8, 243u8, 75u8, 174u8, 125u8, 50u8, 54u8, 117u8, 242u8, 208u8, 32u8, 103u8, 177u8, 246u8, 1u8, 43u8, 229u8, 27u8, 125u8, 79u8, 58u8, 83u8, 253u8, 155u8, 23u8, 231u8, 183u8, 118u8, 200u8, 45u8, 254u8, 177u8, 24u8, 229u8, 151u8, 84u8, 93u8, 191u8, 209u8, 247u8, 212u8, 69u8, 200u8, 194u8, 158u8, 52u8, 157u8, 126u8, 136u8, 182u8, 18u8, 249u8, 34u8, 112u8, 109u8, 8u8];
        let public_inputs = vector[208u8, 241u8, 90u8, 28u8, 103u8, 15u8, 165u8, 81u8, 114u8, 249u8, 52u8, 22u8, 240u8, 197u8, 89u8, 215u8, 132u8, 185u8, 140u8, 252u8, 255u8, 186u8, 70u8, 12u8, 40u8, 215u8, 117u8, 37u8, 145u8, 192u8, 77u8, 9u8, 0u8, 225u8, 245u8, 5u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8];
        
        let ctx = test_scenario::ctx(&mut scenario);
        // This should fail because the VK doesn't match the proof
        proximity::verify_proximity_proof(&mut commitment, vk_bytes, proof_bytes, public_inputs, ctx);
        
        test_scenario::return_shared(commitment);
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

    // Create commitment
    scenario.next_tx(@0x1);
    {
        let server_cap = test_scenario::take_from_sender<proximity::ServerCap>(&scenario);
        let commitment_bytes = vector[208u8, 241u8, 90u8, 28u8, 103u8, 15u8, 165u8, 81u8, 114u8, 249u8, 52u8, 22u8, 240u8, 197u8, 89u8, 215u8, 132u8, 185u8, 140u8, 252u8, 255u8, 186u8, 70u8, 12u8, 40u8, 215u8, 117u8, 37u8, 145u8, 192u8, 77u8, 9u8];
        let owner = @0x2;
        
        let ctx = test_scenario::ctx(&mut scenario);
        proximity::create_commitment(&server_cap, commitment_bytes, owner, ctx);
        
        test_scenario::return_to_sender(&scenario, server_cap);
    };

    // Try to verify with wrong public inputs - should fail
    scenario.next_tx(@0x2);
    {
        let mut commitment = test_scenario::take_shared<proximity::LocationCommitment>(&scenario);
        let vk_bytes = vector[213u8, 160u8, 24u8, 127u8, 138u8, 1u8, 43u8, 90u8, 203u8, 76u8, 89u8, 116u8, 207u8, 63u8, 91u8, 129u8, 252u8, 251u8, 120u8, 195u8, 22u8, 5u8, 90u8, 100u8, 123u8, 8u8, 111u8, 246u8, 206u8, 137u8, 50u8, 39u8, 79u8, 35u8, 204u8, 118u8, 101u8, 50u8, 47u8, 52u8, 84u8, 43u8, 114u8, 168u8, 29u8, 158u8, 91u8, 46u8, 212u8, 194u8, 43u8, 145u8, 117u8, 216u8, 98u8, 128u8, 208u8, 45u8, 172u8, 137u8, 225u8, 46u8, 188u8, 38u8, 172u8, 179u8, 167u8, 0u8, 22u8, 9u8, 237u8, 33u8, 25u8, 148u8, 133u8, 144u8, 168u8, 128u8, 33u8, 171u8, 74u8, 117u8, 57u8, 25u8, 32u8, 155u8, 145u8, 212u8, 149u8, 229u8, 193u8, 247u8, 48u8, 235u8, 129u8, 44u8, 231u8, 169u8, 110u8, 212u8, 148u8, 35u8, 240u8, 35u8, 100u8, 60u8, 146u8, 26u8, 4u8, 231u8, 77u8, 153u8, 122u8, 172u8, 181u8, 50u8, 147u8, 17u8, 211u8, 42u8, 218u8, 79u8, 204u8, 168u8, 167u8, 13u8, 163u8, 38u8, 27u8, 121u8, 137u8, 161u8, 89u8, 207u8, 240u8, 171u8, 235u8, 120u8, 230u8, 102u8, 139u8, 81u8, 152u8, 123u8, 214u8, 238u8, 6u8, 195u8, 249u8, 77u8, 220u8, 67u8, 183u8, 119u8, 206u8, 98u8, 38u8, 167u8, 201u8, 135u8, 56u8, 165u8, 219u8, 184u8, 86u8, 197u8, 7u8, 114u8, 132u8, 16u8, 135u8, 239u8, 213u8, 131u8, 71u8, 188u8, 37u8, 112u8, 176u8, 20u8, 162u8, 12u8, 138u8, 221u8, 129u8, 221u8, 196u8, 10u8, 41u8, 102u8, 75u8, 3u8, 205u8, 86u8, 121u8, 60u8, 244u8, 245u8, 169u8, 184u8, 233u8, 148u8, 223u8, 80u8, 195u8, 155u8, 203u8, 18u8, 44u8, 159u8, 195u8, 50u8, 68u8, 235u8, 178u8, 158u8, 107u8, 91u8, 161u8, 228u8, 69u8, 7u8, 42u8, 165u8, 3u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 7u8, 54u8, 105u8, 92u8, 115u8, 48u8, 82u8, 67u8, 103u8, 158u8, 117u8, 10u8, 159u8, 255u8, 207u8, 242u8, 234u8, 78u8, 210u8, 176u8, 176u8, 42u8, 9u8, 12u8, 236u8, 220u8, 4u8, 180u8, 159u8, 69u8, 222u8, 13u8, 195u8, 94u8, 153u8, 121u8, 80u8, 125u8, 248u8, 176u8, 2u8, 152u8, 134u8, 72u8, 105u8, 187u8, 177u8, 55u8, 48u8, 138u8, 63u8, 23u8, 165u8, 181u8, 7u8, 242u8, 69u8, 238u8, 176u8, 217u8, 139u8, 8u8, 245u8, 16u8, 189u8, 221u8, 70u8, 86u8, 111u8, 172u8, 13u8, 136u8, 162u8, 97u8, 30u8, 137u8, 99u8, 10u8, 183u8, 30u8, 106u8, 181u8, 2u8, 65u8, 211u8, 63u8, 187u8, 243u8, 196u8, 126u8, 252u8, 4u8, 107u8, 196u8, 247u8, 153u8];
        let proof_bytes = vector[28u8, 214u8, 92u8, 71u8, 105u8, 102u8, 199u8, 206u8, 119u8, 146u8, 221u8, 184u8, 2u8, 112u8, 10u8, 139u8, 240u8, 146u8, 142u8, 233u8, 47u8, 9u8, 162u8, 9u8, 203u8, 132u8, 181u8, 119u8, 238u8, 111u8, 252u8, 166u8, 236u8, 23u8, 189u8, 227u8, 253u8, 151u8, 248u8, 11u8, 102u8, 163u8, 226u8, 225u8, 96u8, 97u8, 64u8, 225u8, 107u8, 102u8, 109u8, 165u8, 11u8, 84u8, 25u8, 118u8, 77u8, 244u8, 9u8, 1u8, 206u8, 201u8, 110u8, 19u8, 240u8, 97u8, 247u8, 148u8, 10u8, 250u8, 74u8, 51u8, 90u8, 243u8, 75u8, 174u8, 125u8, 50u8, 54u8, 117u8, 242u8, 208u8, 32u8, 103u8, 177u8, 246u8, 1u8, 43u8, 229u8, 27u8, 125u8, 79u8, 58u8, 83u8, 253u8, 155u8, 23u8, 231u8, 183u8, 118u8, 200u8, 45u8, 254u8, 177u8, 24u8, 229u8, 151u8, 84u8, 93u8, 191u8, 209u8, 247u8, 212u8, 69u8, 200u8, 194u8, 158u8, 52u8, 157u8, 126u8, 136u8, 182u8, 18u8, 249u8, 34u8, 112u8, 109u8, 8u8];
        let public_inputs = vector[208u8, 241u8, 90u8, 28u8, 103u8, 15u8, 165u8, 81u8, 114u8, 249u8, 52u8, 22u8, 240u8, 197u8, 89u8, 215u8, 123u8, 185u8, 140u8, 252u8, 255u8, 186u8, 70u8, 12u8, 40u8, 215u8, 117u8, 37u8, 145u8, 192u8, 77u8, 9u8, 0u8, 225u8, 245u8, 5u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8]; // Wrong public inputs
        
        let ctx = test_scenario::ctx(&mut scenario);
        // This should fail because the public inputs don't match the proof
        proximity::verify_proximity_proof(&mut commitment, vk_bytes, proof_bytes, public_inputs, ctx);
        
        test_scenario::return_shared(commitment);
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

    // Create commitment with different coordinates
    scenario.next_tx(@0x1);
    {
        let server_cap = test_scenario::take_from_sender<proximity::ServerCap>(&scenario);
        let commitment_bytes = vector[236u8, 27u8, 154u8, 100u8, 233u8, 51u8, 120u8, 205u8, 151u8, 180u8, 54u8, 44u8, 42u8, 206u8, 93u8, 56u8, 198u8, 46u8, 70u8, 164u8, 129u8, 27u8, 47u8, 11u8, 24u8, 25u8, 224u8, 190u8, 28u8, 96u8, 10u8, 10u8]; // Different Poseidon commitment hash (32 bytes)
        let owner = @0x3;
        
        let ctx = test_scenario::ctx(&mut scenario);
        proximity::create_commitment(&server_cap, commitment_bytes, owner, ctx);
        
        test_scenario::return_to_sender(&scenario, server_cap);
    };

    // Verify proximity proof with different valid coordinates within 10km
    scenario.next_tx(@0x3);
    {
        let mut commitment = test_scenario::take_shared<proximity::LocationCommitment>(&scenario);
        let vk_bytes = vector[213u8, 160u8, 24u8, 127u8, 138u8, 1u8, 43u8, 90u8, 203u8, 76u8, 89u8, 116u8, 207u8, 63u8, 91u8, 129u8, 252u8, 251u8, 120u8, 195u8, 22u8, 5u8, 90u8, 100u8, 123u8, 8u8, 111u8, 246u8, 206u8, 137u8, 50u8, 39u8, 79u8, 35u8, 204u8, 118u8, 101u8, 50u8, 47u8, 52u8, 84u8, 43u8, 114u8, 168u8, 29u8, 158u8, 91u8, 46u8, 212u8, 194u8, 43u8, 145u8, 117u8, 216u8, 98u8, 128u8, 208u8, 45u8, 172u8, 137u8, 225u8, 46u8, 188u8, 38u8, 172u8, 179u8, 167u8, 0u8, 22u8, 9u8, 237u8, 33u8, 25u8, 148u8, 133u8, 144u8, 168u8, 128u8, 33u8, 171u8, 74u8, 117u8, 57u8, 25u8, 32u8, 155u8, 145u8, 212u8, 149u8, 229u8, 193u8, 247u8, 48u8, 235u8, 129u8, 44u8, 231u8, 169u8, 110u8, 212u8, 148u8, 35u8, 240u8, 35u8, 100u8, 60u8, 146u8, 26u8, 4u8, 231u8, 77u8, 153u8, 122u8, 172u8, 181u8, 50u8, 147u8, 17u8, 211u8, 42u8, 218u8, 79u8, 204u8, 168u8, 167u8, 13u8, 163u8, 38u8, 27u8, 121u8, 137u8, 161u8, 89u8, 207u8, 240u8, 171u8, 235u8, 120u8, 230u8, 102u8, 139u8, 81u8, 152u8, 123u8, 214u8, 238u8, 6u8, 195u8, 249u8, 77u8, 220u8, 67u8, 183u8, 119u8, 206u8, 98u8, 38u8, 167u8, 201u8, 135u8, 56u8, 165u8, 219u8, 184u8, 86u8, 197u8, 7u8, 114u8, 132u8, 16u8, 135u8, 239u8, 213u8, 131u8, 71u8, 188u8, 37u8, 112u8, 176u8, 20u8, 162u8, 12u8, 138u8, 221u8, 129u8, 221u8, 196u8, 10u8, 41u8, 102u8, 75u8, 3u8, 205u8, 86u8, 121u8, 60u8, 244u8, 245u8, 169u8, 184u8, 233u8, 148u8, 223u8, 80u8, 195u8, 155u8, 203u8, 18u8, 44u8, 159u8, 195u8, 50u8, 68u8, 235u8, 178u8, 158u8, 107u8, 91u8, 161u8, 228u8, 69u8, 7u8, 42u8, 165u8, 3u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 7u8, 54u8, 105u8, 92u8, 115u8, 48u8, 82u8, 67u8, 103u8, 158u8, 117u8, 10u8, 159u8, 255u8, 207u8, 242u8, 234u8, 78u8, 210u8, 176u8, 176u8, 42u8, 9u8, 12u8, 236u8, 220u8, 4u8, 180u8, 159u8, 69u8, 222u8, 13u8, 195u8, 94u8, 153u8, 121u8, 80u8, 125u8, 248u8, 176u8, 2u8, 152u8, 134u8, 72u8, 105u8, 187u8, 177u8, 55u8, 48u8, 138u8, 63u8, 23u8, 165u8, 181u8, 7u8, 242u8, 69u8, 238u8, 176u8, 217u8, 139u8, 8u8, 245u8, 16u8, 189u8, 221u8, 70u8, 86u8, 111u8, 172u8, 13u8, 136u8, 162u8, 97u8, 30u8, 137u8, 99u8, 10u8, 183u8, 30u8, 106u8, 181u8, 2u8, 65u8, 211u8, 63u8, 187u8, 243u8, 196u8, 126u8, 252u8, 4u8, 107u8, 196u8, 247u8, 153u8];
        let proof_bytes = vector[105u8, 203u8, 230u8, 131u8, 51u8, 173u8, 33u8, 119u8, 11u8, 141u8, 84u8, 160u8, 49u8, 211u8, 98u8, 15u8, 246u8, 148u8, 68u8, 249u8, 81u8, 3u8, 191u8, 134u8, 104u8, 231u8, 125u8, 59u8, 202u8, 34u8, 81u8, 150u8, 101u8, 122u8, 121u8, 123u8, 200u8, 52u8, 137u8, 160u8, 14u8, 125u8, 111u8, 41u8, 216u8, 97u8, 33u8, 184u8, 66u8, 31u8, 249u8, 151u8, 153u8, 191u8, 197u8, 207u8, 198u8, 240u8, 66u8, 175u8, 71u8, 71u8, 0u8, 5u8, 166u8, 196u8, 141u8, 232u8, 54u8, 124u8, 175u8, 227u8, 109u8, 98u8, 7u8, 217u8, 243u8, 150u8, 152u8, 155u8, 162u8, 32u8, 40u8, 113u8, 0u8, 197u8, 181u8, 110u8, 148u8, 124u8, 231u8, 145u8, 42u8, 95u8, 40u8, 43u8, 159u8, 130u8, 219u8, 85u8, 89u8, 43u8, 188u8, 81u8, 136u8, 46u8, 155u8, 216u8, 82u8, 0u8, 88u8, 226u8, 41u8, 252u8, 192u8, 60u8, 133u8, 193u8, 48u8, 238u8, 54u8, 37u8, 95u8, 209u8, 140u8, 146u8, 245u8, 147u8];
        let public_inputs = vector[236u8, 27u8, 154u8, 100u8, 233u8, 51u8, 120u8, 205u8, 151u8, 180u8, 54u8, 44u8, 42u8, 206u8, 93u8, 56u8, 198u8, 46u8, 70u8, 164u8, 129u8, 27u8, 47u8, 11u8, 24u8, 25u8, 224u8, 190u8, 28u8, 96u8, 10u8, 10u8, 0u8, 225u8, 245u8, 5u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8];
        
        let ctx = test_scenario::ctx(&mut scenario);
        proximity::verify_proximity_proof(&mut commitment, vk_bytes, proof_bytes, public_inputs, ctx);
        
        // Verify nonce was incremented
        let nonce = proximity::get_nonce(&commitment);
        assert!(nonce == 1, 0);
        
        test_scenario::return_shared(commitment);
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

    // Create commitment with absolute value coordinates
    scenario.next_tx(@0x1);
    {
        let server_cap = test_scenario::take_from_sender<proximity::ServerCap>(&scenario);
        let commitment_bytes = vector[244u8, 40u8, 41u8, 99u8, 74u8, 198u8, 42u8, 25u8, 89u8, 101u8, 173u8, 82u8, 141u8, 46u8, 40u8, 172u8, 29u8, 186u8, 63u8, 73u8, 43u8, 204u8, 174u8, 125u8, 49u8, 44u8, 71u8, 35u8, 208u8, 118u8, 50u8, 7u8]; // Absolute value Poseidon commitment hash (32 bytes)
        let owner = @0x4;
        
        let ctx = test_scenario::ctx(&mut scenario);
        proximity::create_commitment(&server_cap, commitment_bytes, owner, ctx);
        
        test_scenario::return_to_sender(&scenario, server_cap);
    };

    // Verify proximity proof with absolute value coordinates
    scenario.next_tx(@0x4);
    {
        let mut commitment = test_scenario::take_shared<proximity::LocationCommitment>(&scenario);
        let vk_bytes = vector[213u8, 160u8, 24u8, 127u8, 138u8, 1u8, 43u8, 90u8, 203u8, 76u8, 89u8, 116u8, 207u8, 63u8, 91u8, 129u8, 252u8, 251u8, 120u8, 195u8, 22u8, 5u8, 90u8, 100u8, 123u8, 8u8, 111u8, 246u8, 206u8, 137u8, 50u8, 39u8, 79u8, 35u8, 204u8, 118u8, 101u8, 50u8, 47u8, 52u8, 84u8, 43u8, 114u8, 168u8, 29u8, 158u8, 91u8, 46u8, 212u8, 194u8, 43u8, 145u8, 117u8, 216u8, 98u8, 128u8, 208u8, 45u8, 172u8, 137u8, 225u8, 46u8, 188u8, 38u8, 172u8, 179u8, 167u8, 0u8, 22u8, 9u8, 237u8, 33u8, 25u8, 148u8, 133u8, 144u8, 168u8, 128u8, 33u8, 171u8, 74u8, 117u8, 57u8, 25u8, 32u8, 155u8, 145u8, 212u8, 149u8, 229u8, 193u8, 247u8, 48u8, 235u8, 129u8, 44u8, 231u8, 169u8, 110u8, 212u8, 148u8, 35u8, 240u8, 35u8, 100u8, 60u8, 146u8, 26u8, 4u8, 231u8, 77u8, 153u8, 122u8, 172u8, 181u8, 50u8, 147u8, 17u8, 211u8, 42u8, 218u8, 79u8, 204u8, 168u8, 167u8, 13u8, 163u8, 38u8, 27u8, 121u8, 137u8, 161u8, 89u8, 207u8, 240u8, 171u8, 235u8, 120u8, 230u8, 102u8, 139u8, 81u8, 152u8, 123u8, 214u8, 238u8, 6u8, 195u8, 249u8, 77u8, 220u8, 67u8, 183u8, 119u8, 206u8, 98u8, 38u8, 167u8, 201u8, 135u8, 56u8, 165u8, 219u8, 184u8, 86u8, 197u8, 7u8, 114u8, 132u8, 16u8, 135u8, 239u8, 213u8, 131u8, 71u8, 188u8, 37u8, 112u8, 176u8, 20u8, 162u8, 12u8, 138u8, 221u8, 129u8, 221u8, 196u8, 10u8, 41u8, 102u8, 75u8, 3u8, 205u8, 86u8, 121u8, 60u8, 244u8, 245u8, 169u8, 184u8, 233u8, 148u8, 223u8, 80u8, 195u8, 155u8, 203u8, 18u8, 44u8, 159u8, 195u8, 50u8, 68u8, 235u8, 178u8, 158u8, 107u8, 91u8, 161u8, 228u8, 69u8, 7u8, 42u8, 165u8, 3u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 7u8, 54u8, 105u8, 92u8, 115u8, 48u8, 82u8, 67u8, 103u8, 158u8, 117u8, 10u8, 159u8, 255u8, 207u8, 242u8, 234u8, 78u8, 210u8, 176u8, 176u8, 42u8, 9u8, 12u8, 236u8, 220u8, 4u8, 180u8, 159u8, 69u8, 222u8, 13u8, 195u8, 94u8, 153u8, 121u8, 80u8, 125u8, 248u8, 176u8, 2u8, 152u8, 134u8, 72u8, 105u8, 187u8, 177u8, 55u8, 48u8, 138u8, 63u8, 23u8, 165u8, 181u8, 7u8, 242u8, 69u8, 238u8, 176u8, 217u8, 139u8, 8u8, 245u8, 16u8, 189u8, 221u8, 70u8, 86u8, 111u8, 172u8, 13u8, 136u8, 162u8, 97u8, 30u8, 137u8, 99u8, 10u8, 183u8, 30u8, 106u8, 181u8, 2u8, 65u8, 211u8, 63u8, 187u8, 243u8, 196u8, 126u8, 252u8, 4u8, 107u8, 196u8, 247u8, 153u8];
        let proof_bytes = vector[28u8, 214u8, 92u8, 71u8, 105u8, 102u8, 199u8, 206u8, 119u8, 146u8, 221u8, 184u8, 2u8, 112u8, 10u8, 139u8, 240u8, 146u8, 142u8, 233u8, 47u8, 9u8, 162u8, 9u8, 203u8, 132u8, 181u8, 119u8, 238u8, 111u8, 252u8, 166u8, 236u8, 23u8, 189u8, 227u8, 253u8, 151u8, 248u8, 11u8, 102u8, 163u8, 226u8, 225u8, 96u8, 97u8, 64u8, 225u8, 107u8, 102u8, 109u8, 165u8, 11u8, 84u8, 25u8, 118u8, 77u8, 244u8, 9u8, 1u8, 206u8, 201u8, 110u8, 19u8, 240u8, 97u8, 247u8, 148u8, 10u8, 250u8, 74u8, 51u8, 90u8, 243u8, 75u8, 174u8, 125u8, 50u8, 54u8, 117u8, 242u8, 208u8, 32u8, 103u8, 177u8, 246u8, 1u8, 43u8, 229u8, 27u8, 125u8, 79u8, 58u8, 83u8, 253u8, 155u8, 23u8, 231u8, 183u8, 118u8, 200u8, 45u8, 254u8, 177u8, 24u8, 229u8, 151u8, 84u8, 93u8, 191u8, 209u8, 247u8, 212u8, 69u8, 200u8, 194u8, 158u8, 52u8, 157u8, 126u8, 136u8, 182u8, 18u8, 249u8, 34u8, 112u8, 109u8, 8u8];
        let public_inputs = vector[208u8, 241u8, 90u8, 28u8, 103u8, 15u8, 165u8, 81u8, 114u8, 249u8, 52u8, 22u8, 240u8, 197u8, 89u8, 215u8, 132u8, 185u8, 140u8, 252u8, 255u8, 186u8, 70u8, 12u8, 40u8, 215u8, 117u8, 37u8, 145u8, 192u8, 77u8, 9u8, 0u8, 225u8, 245u8, 5u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8];
        
        let ctx = test_scenario::ctx(&mut scenario);
        proximity::verify_proximity_proof(&mut commitment, vk_bytes, proof_bytes, public_inputs, ctx);
        
        // Verify nonce was incremented
        let nonce = proximity::get_nonce(&commitment);
        assert!(nonce == 1, 0);
        
        test_scenario::return_shared(commitment);
    };

    test_scenario::end(scenario);
}
