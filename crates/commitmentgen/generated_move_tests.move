
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
        let commitment_bytes = vector[137u8, 190u8, 189u8, 224u8, 185u8, 209u8, 74u8, 149u8, 149u8, 207u8, 42u8, 238u8, 208u8, 119u8, 101u8, 45u8, 176u8, 210u8, 221u8, 28u8, 11u8, 190u8, 176u8, 102u8, 242u8, 50u8, 127u8, 41u8, 236u8, 78u8, 200u8, 46u8]; // Poseidon hash (32 bytes)
        let owner = @0x2;
        
        let ctx = test_scenario::ctx(&mut scenario);
        proximity::create_commitment(&server_cap, commitment_bytes, owner, ctx);
        
        test_scenario::return_to_sender(&scenario, server_cap);
    };

    // Verify proximity proof
    scenario.next_tx(@0x2);
    {
        let mut commitment = test_scenario::take_shared<proximity::LocationCommitment>(&scenario);
        let vk_bytes = vector[142u8, 37u8, 216u8, 229u8, 250u8, 242u8, 171u8, 206u8, 84u8, 37u8, 34u8, 116u8, 74u8, 153u8, 143u8, 251u8, 152u8, 121u8, 224u8, 155u8, 202u8, 38u8, 110u8, 232u8, 34u8, 50u8, 98u8, 201u8, 26u8, 221u8, 159u8, 147u8, 171u8, 47u8, 125u8, 125u8, 170u8, 98u8, 75u8, 153u8, 165u8, 21u8, 226u8, 200u8, 181u8, 59u8, 37u8, 162u8, 120u8, 153u8, 31u8, 150u8, 134u8, 60u8, 147u8, 165u8, 86u8, 248u8, 53u8, 216u8, 4u8, 185u8, 246u8, 38u8, 164u8, 73u8, 7u8, 80u8, 134u8, 20u8, 43u8, 119u8, 101u8, 140u8, 240u8, 70u8, 159u8, 236u8, 97u8, 249u8, 223u8, 81u8, 191u8, 85u8, 4u8, 170u8, 56u8, 35u8, 183u8, 217u8, 182u8, 140u8, 54u8, 57u8, 237u8, 27u8, 101u8, 123u8, 178u8, 95u8, 169u8, 230u8, 219u8, 16u8, 140u8, 255u8, 12u8, 183u8, 157u8, 46u8, 45u8, 249u8, 126u8, 189u8, 190u8, 40u8, 169u8, 98u8, 36u8, 93u8, 112u8, 32u8, 75u8, 157u8, 3u8, 132u8, 251u8, 41u8, 53u8, 134u8, 124u8, 69u8, 240u8, 171u8, 16u8, 248u8, 132u8, 185u8, 17u8, 152u8, 237u8, 217u8, 200u8, 246u8, 54u8, 93u8, 150u8, 124u8, 60u8, 39u8, 187u8, 188u8, 141u8, 100u8, 55u8, 186u8, 151u8, 151u8, 91u8, 145u8, 6u8, 229u8, 198u8, 38u8, 82u8, 219u8, 102u8, 224u8, 123u8, 151u8, 61u8, 121u8, 129u8, 224u8, 22u8, 53u8, 146u8, 18u8, 190u8, 243u8, 156u8, 113u8, 98u8, 117u8, 143u8, 24u8, 161u8, 1u8, 170u8, 241u8, 237u8, 47u8, 202u8, 195u8, 199u8, 128u8, 254u8, 182u8, 19u8, 11u8, 119u8, 19u8, 253u8, 170u8, 73u8, 177u8, 249u8, 253u8, 131u8, 62u8, 126u8, 31u8, 221u8, 161u8, 67u8, 134u8, 106u8, 35u8, 58u8, 166u8, 32u8, 217u8, 216u8, 168u8, 3u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 165u8, 243u8, 106u8, 227u8, 36u8, 215u8, 177u8, 185u8, 192u8, 144u8, 4u8, 24u8, 137u8, 84u8, 157u8, 226u8, 137u8, 81u8, 71u8, 133u8, 176u8, 2u8, 82u8, 99u8, 102u8, 167u8, 205u8, 54u8, 60u8, 183u8, 154u8, 165u8, 85u8, 131u8, 141u8, 239u8, 143u8, 85u8, 138u8, 35u8, 167u8, 132u8, 185u8, 64u8, 231u8, 18u8, 94u8, 211u8, 101u8, 64u8, 173u8, 83u8, 94u8, 151u8, 207u8, 220u8, 77u8, 235u8, 250u8, 81u8, 223u8, 211u8, 104u8, 145u8, 215u8, 244u8, 122u8, 65u8, 118u8, 47u8, 156u8, 109u8, 71u8, 37u8, 114u8, 98u8, 95u8, 113u8, 199u8, 134u8, 161u8, 152u8, 169u8, 157u8, 104u8, 45u8, 185u8, 148u8, 79u8, 1u8, 219u8, 7u8, 254u8, 136u8, 37u8, 47u8];
        let proof_bytes = vector[180u8, 138u8, 178u8, 155u8, 151u8, 139u8, 244u8, 99u8, 183u8, 37u8, 4u8, 85u8, 235u8, 121u8, 115u8, 235u8, 77u8, 69u8, 203u8, 250u8, 35u8, 11u8, 204u8, 204u8, 14u8, 32u8, 221u8, 215u8, 30u8, 88u8, 81u8, 151u8, 227u8, 112u8, 238u8, 247u8, 125u8, 226u8, 88u8, 23u8, 157u8, 221u8, 55u8, 37u8, 120u8, 220u8, 8u8, 160u8, 204u8, 232u8, 87u8, 243u8, 250u8, 124u8, 66u8, 93u8, 95u8, 10u8, 11u8, 79u8, 246u8, 158u8, 237u8, 28u8, 167u8, 172u8, 205u8, 100u8, 235u8, 144u8, 145u8, 120u8, 131u8, 120u8, 1u8, 187u8, 255u8, 17u8, 176u8, 74u8, 146u8, 69u8, 137u8, 105u8, 206u8, 141u8, 195u8, 156u8, 171u8, 73u8, 236u8, 236u8, 154u8, 51u8, 133u8, 142u8, 253u8, 241u8, 80u8, 101u8, 124u8, 56u8, 172u8, 65u8, 26u8, 224u8, 85u8, 50u8, 95u8, 115u8, 199u8, 64u8, 192u8, 119u8, 125u8, 191u8, 172u8, 102u8, 109u8, 155u8, 192u8, 206u8, 130u8, 131u8, 149u8, 87u8, 167u8, 155u8];
        let public_inputs = vector[137u8, 190u8, 189u8, 224u8, 185u8, 209u8, 74u8, 149u8, 149u8, 207u8, 42u8, 238u8, 208u8, 119u8, 101u8, 45u8, 176u8, 210u8, 221u8, 28u8, 11u8, 190u8, 176u8, 102u8, 242u8, 50u8, 127u8, 41u8, 236u8, 78u8, 200u8, 46u8, 0u8, 225u8, 245u8, 5u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8]; // [commitment_hash, max_distance_squared] (64 bytes total)
        
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
        let commitment_bytes = vector[137u8, 190u8, 189u8, 224u8, 185u8, 209u8, 74u8, 149u8, 149u8, 207u8, 42u8, 238u8, 208u8, 119u8, 101u8, 45u8, 176u8, 210u8, 221u8, 28u8, 11u8, 190u8, 176u8, 102u8, 242u8, 50u8, 127u8, 41u8, 236u8, 78u8, 200u8, 46u8];
        let owner = @0x2;
        
        let ctx = test_scenario::ctx(&mut scenario);
        proximity::create_commitment(&server_cap, commitment_bytes, owner, ctx);
        
        test_scenario::return_to_sender(&scenario, server_cap);
    };

    // Try to verify with corrupted proof - should fail
    scenario.next_tx(@0x2);
    {
        let mut commitment = test_scenario::take_shared<proximity::LocationCommitment>(&scenario);
        let vk_bytes = vector[142u8, 37u8, 216u8, 229u8, 250u8, 242u8, 171u8, 206u8, 84u8, 37u8, 34u8, 116u8, 74u8, 153u8, 143u8, 251u8, 152u8, 121u8, 224u8, 155u8, 202u8, 38u8, 110u8, 232u8, 34u8, 50u8, 98u8, 201u8, 26u8, 221u8, 159u8, 147u8, 171u8, 47u8, 125u8, 125u8, 170u8, 98u8, 75u8, 153u8, 165u8, 21u8, 226u8, 200u8, 181u8, 59u8, 37u8, 162u8, 120u8, 153u8, 31u8, 150u8, 134u8, 60u8, 147u8, 165u8, 86u8, 248u8, 53u8, 216u8, 4u8, 185u8, 246u8, 38u8, 164u8, 73u8, 7u8, 80u8, 134u8, 20u8, 43u8, 119u8, 101u8, 140u8, 240u8, 70u8, 159u8, 236u8, 97u8, 249u8, 223u8, 81u8, 191u8, 85u8, 4u8, 170u8, 56u8, 35u8, 183u8, 217u8, 182u8, 140u8, 54u8, 57u8, 237u8, 27u8, 101u8, 123u8, 178u8, 95u8, 169u8, 230u8, 219u8, 16u8, 140u8, 255u8, 12u8, 183u8, 157u8, 46u8, 45u8, 249u8, 126u8, 189u8, 190u8, 40u8, 169u8, 98u8, 36u8, 93u8, 112u8, 32u8, 75u8, 157u8, 3u8, 132u8, 251u8, 41u8, 53u8, 134u8, 124u8, 69u8, 240u8, 171u8, 16u8, 248u8, 132u8, 185u8, 17u8, 152u8, 237u8, 217u8, 200u8, 246u8, 54u8, 93u8, 150u8, 124u8, 60u8, 39u8, 187u8, 188u8, 141u8, 100u8, 55u8, 186u8, 151u8, 151u8, 91u8, 145u8, 6u8, 229u8, 198u8, 38u8, 82u8, 219u8, 102u8, 224u8, 123u8, 151u8, 61u8, 121u8, 129u8, 224u8, 22u8, 53u8, 146u8, 18u8, 190u8, 243u8, 156u8, 113u8, 98u8, 117u8, 143u8, 24u8, 161u8, 1u8, 170u8, 241u8, 237u8, 47u8, 202u8, 195u8, 199u8, 128u8, 254u8, 182u8, 19u8, 11u8, 119u8, 19u8, 253u8, 170u8, 73u8, 177u8, 249u8, 253u8, 131u8, 62u8, 126u8, 31u8, 221u8, 161u8, 67u8, 134u8, 106u8, 35u8, 58u8, 166u8, 32u8, 217u8, 216u8, 168u8, 3u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 165u8, 243u8, 106u8, 227u8, 36u8, 215u8, 177u8, 185u8, 192u8, 144u8, 4u8, 24u8, 137u8, 84u8, 157u8, 226u8, 137u8, 81u8, 71u8, 133u8, 176u8, 2u8, 82u8, 99u8, 102u8, 167u8, 205u8, 54u8, 60u8, 183u8, 154u8, 165u8, 85u8, 131u8, 141u8, 239u8, 143u8, 85u8, 138u8, 35u8, 167u8, 132u8, 185u8, 64u8, 231u8, 18u8, 94u8, 211u8, 101u8, 64u8, 173u8, 83u8, 94u8, 151u8, 207u8, 220u8, 77u8, 235u8, 250u8, 81u8, 223u8, 211u8, 104u8, 145u8, 215u8, 244u8, 122u8, 65u8, 118u8, 47u8, 156u8, 109u8, 71u8, 37u8, 114u8, 98u8, 95u8, 113u8, 199u8, 134u8, 161u8, 152u8, 169u8, 157u8, 104u8, 45u8, 185u8, 148u8, 79u8, 1u8, 219u8, 7u8, 254u8, 136u8, 37u8, 47u8];
        let proof_bytes = vector[180u8, 138u8, 178u8, 155u8, 151u8, 139u8, 244u8, 99u8, 183u8, 37u8, 251u8, 85u8, 235u8, 121u8, 115u8, 235u8, 77u8, 69u8, 203u8, 250u8, 35u8, 11u8, 204u8, 204u8, 14u8, 32u8, 221u8, 215u8, 30u8, 88u8, 81u8, 151u8, 227u8, 112u8, 238u8, 247u8, 125u8, 226u8, 88u8, 23u8, 157u8, 221u8, 55u8, 37u8, 120u8, 220u8, 8u8, 160u8, 204u8, 232u8, 87u8, 243u8, 250u8, 124u8, 66u8, 93u8, 95u8, 10u8, 11u8, 79u8, 246u8, 158u8, 237u8, 28u8, 167u8, 172u8, 205u8, 100u8, 235u8, 144u8, 145u8, 120u8, 131u8, 120u8, 1u8, 187u8, 255u8, 17u8, 176u8, 74u8, 146u8, 69u8, 137u8, 105u8, 206u8, 141u8, 195u8, 156u8, 171u8, 73u8, 236u8, 236u8, 154u8, 51u8, 133u8, 142u8, 253u8, 241u8, 80u8, 101u8, 124u8, 56u8, 172u8, 65u8, 26u8, 224u8, 85u8, 50u8, 95u8, 115u8, 199u8, 64u8, 192u8, 119u8, 125u8, 191u8, 172u8, 102u8, 109u8, 155u8, 192u8, 206u8, 130u8, 131u8, 149u8, 87u8, 167u8, 155u8]; // Corrupted proof bytes
        let public_inputs = vector[137u8, 190u8, 189u8, 224u8, 185u8, 209u8, 74u8, 149u8, 149u8, 207u8, 42u8, 238u8, 208u8, 119u8, 101u8, 45u8, 176u8, 210u8, 221u8, 28u8, 11u8, 190u8, 176u8, 102u8, 242u8, 50u8, 127u8, 41u8, 236u8, 78u8, 200u8, 46u8, 0u8, 225u8, 245u8, 5u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8];
        
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
        let commitment_bytes = vector[137u8, 190u8, 189u8, 224u8, 185u8, 209u8, 74u8, 149u8, 149u8, 207u8, 42u8, 238u8, 208u8, 119u8, 101u8, 45u8, 176u8, 210u8, 221u8, 28u8, 11u8, 190u8, 176u8, 102u8, 242u8, 50u8, 127u8, 41u8, 236u8, 78u8, 200u8, 46u8];
        let owner = @0x2;
        
        let ctx = test_scenario::ctx(&mut scenario);
        proximity::create_commitment(&server_cap, commitment_bytes, owner, ctx);
        
        test_scenario::return_to_sender(&scenario, server_cap);
    };

    // Try to verify with wrong verification key - should fail
    scenario.next_tx(@0x2);
    {
        let mut commitment = test_scenario::take_shared<proximity::LocationCommitment>(&scenario);
        let vk_bytes = vector[223u8, 248u8, 67u8, 67u8, 87u8, 146u8, 114u8, 144u8, 195u8, 221u8, 169u8, 137u8, 229u8, 136u8, 71u8, 192u8, 13u8, 103u8, 0u8, 201u8, 134u8, 190u8, 190u8, 167u8, 120u8, 44u8, 226u8, 158u8, 114u8, 136u8, 231u8, 157u8, 243u8, 27u8, 181u8, 217u8, 23u8, 3u8, 173u8, 193u8, 8u8, 247u8, 80u8, 90u8, 228u8, 98u8, 157u8, 39u8, 172u8, 52u8, 49u8, 164u8, 189u8, 56u8, 116u8, 185u8, 122u8, 218u8, 126u8, 77u8, 202u8, 196u8, 172u8, 39u8, 101u8, 3u8, 112u8, 85u8, 186u8, 31u8, 112u8, 64u8, 230u8, 191u8, 143u8, 205u8, 139u8, 159u8, 23u8, 99u8, 100u8, 36u8, 108u8, 181u8, 212u8, 60u8, 214u8, 204u8, 86u8, 62u8, 170u8, 205u8, 123u8, 16u8, 248u8, 144u8, 156u8, 46u8, 102u8, 166u8, 14u8, 65u8, 219u8, 202u8, 46u8, 59u8, 34u8, 60u8, 246u8, 12u8, 69u8, 153u8, 166u8, 250u8, 247u8, 35u8, 183u8, 128u8, 63u8, 14u8, 217u8, 7u8, 220u8, 107u8, 7u8, 192u8, 233u8, 16u8, 225u8, 201u8, 6u8, 152u8, 84u8, 247u8, 217u8, 15u8, 115u8, 234u8, 43u8, 95u8, 242u8, 32u8, 173u8, 226u8, 82u8, 11u8, 185u8, 249u8, 183u8, 50u8, 66u8, 159u8, 75u8, 223u8, 69u8, 202u8, 152u8, 217u8, 106u8, 8u8, 82u8, 187u8, 14u8, 179u8, 64u8, 23u8, 206u8, 199u8, 195u8, 125u8, 126u8, 83u8, 160u8, 112u8, 212u8, 184u8, 194u8, 162u8, 170u8, 174u8, 57u8, 78u8, 219u8, 119u8, 20u8, 238u8, 69u8, 129u8, 15u8, 104u8, 254u8, 29u8, 206u8, 115u8, 63u8, 89u8, 130u8, 93u8, 1u8, 212u8, 14u8, 197u8, 217u8, 234u8, 72u8, 149u8, 65u8, 139u8, 46u8, 21u8, 54u8, 123u8, 165u8, 72u8, 10u8, 190u8, 32u8, 226u8, 146u8, 238u8, 231u8, 176u8, 171u8, 166u8, 3u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 74u8, 66u8, 54u8, 235u8, 115u8, 168u8, 92u8, 132u8, 164u8, 4u8, 61u8, 248u8, 59u8, 118u8, 236u8, 32u8, 121u8, 214u8, 205u8, 75u8, 6u8, 138u8, 160u8, 255u8, 11u8, 123u8, 1u8, 118u8, 73u8, 33u8, 63u8, 33u8, 146u8, 145u8, 59u8, 164u8, 62u8, 156u8, 139u8, 76u8, 183u8, 235u8, 155u8, 203u8, 27u8, 157u8, 91u8, 26u8, 46u8, 78u8, 50u8, 229u8, 47u8, 148u8, 16u8, 140u8, 64u8, 223u8, 68u8, 124u8, 94u8, 91u8, 201u8, 168u8, 10u8, 4u8, 137u8, 150u8, 239u8, 65u8, 149u8, 188u8, 204u8, 170u8, 213u8, 142u8, 191u8, 104u8, 143u8, 105u8, 8u8, 46u8, 88u8, 75u8, 30u8, 132u8, 209u8, 72u8, 124u8, 101u8, 17u8, 159u8, 16u8, 201u8, 132u8, 139u8]; // Wrong VK bytes
        let proof_bytes = vector[180u8, 138u8, 178u8, 155u8, 151u8, 139u8, 244u8, 99u8, 183u8, 37u8, 4u8, 85u8, 235u8, 121u8, 115u8, 235u8, 77u8, 69u8, 203u8, 250u8, 35u8, 11u8, 204u8, 204u8, 14u8, 32u8, 221u8, 215u8, 30u8, 88u8, 81u8, 151u8, 227u8, 112u8, 238u8, 247u8, 125u8, 226u8, 88u8, 23u8, 157u8, 221u8, 55u8, 37u8, 120u8, 220u8, 8u8, 160u8, 204u8, 232u8, 87u8, 243u8, 250u8, 124u8, 66u8, 93u8, 95u8, 10u8, 11u8, 79u8, 246u8, 158u8, 237u8, 28u8, 167u8, 172u8, 205u8, 100u8, 235u8, 144u8, 145u8, 120u8, 131u8, 120u8, 1u8, 187u8, 255u8, 17u8, 176u8, 74u8, 146u8, 69u8, 137u8, 105u8, 206u8, 141u8, 195u8, 156u8, 171u8, 73u8, 236u8, 236u8, 154u8, 51u8, 133u8, 142u8, 253u8, 241u8, 80u8, 101u8, 124u8, 56u8, 172u8, 65u8, 26u8, 224u8, 85u8, 50u8, 95u8, 115u8, 199u8, 64u8, 192u8, 119u8, 125u8, 191u8, 172u8, 102u8, 109u8, 155u8, 192u8, 206u8, 130u8, 131u8, 149u8, 87u8, 167u8, 155u8];
        let public_inputs = vector[137u8, 190u8, 189u8, 224u8, 185u8, 209u8, 74u8, 149u8, 149u8, 207u8, 42u8, 238u8, 208u8, 119u8, 101u8, 45u8, 176u8, 210u8, 221u8, 28u8, 11u8, 190u8, 176u8, 102u8, 242u8, 50u8, 127u8, 41u8, 236u8, 78u8, 200u8, 46u8, 0u8, 225u8, 245u8, 5u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8];
        
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
        let commitment_bytes = vector[137u8, 190u8, 189u8, 224u8, 185u8, 209u8, 74u8, 149u8, 149u8, 207u8, 42u8, 238u8, 208u8, 119u8, 101u8, 45u8, 176u8, 210u8, 221u8, 28u8, 11u8, 190u8, 176u8, 102u8, 242u8, 50u8, 127u8, 41u8, 236u8, 78u8, 200u8, 46u8];
        let owner = @0x2;
        
        let ctx = test_scenario::ctx(&mut scenario);
        proximity::create_commitment(&server_cap, commitment_bytes, owner, ctx);
        
        test_scenario::return_to_sender(&scenario, server_cap);
    };

    // Try to verify with wrong public inputs - should fail
    scenario.next_tx(@0x2);
    {
        let mut commitment = test_scenario::take_shared<proximity::LocationCommitment>(&scenario);
        let vk_bytes = vector[142u8, 37u8, 216u8, 229u8, 250u8, 242u8, 171u8, 206u8, 84u8, 37u8, 34u8, 116u8, 74u8, 153u8, 143u8, 251u8, 152u8, 121u8, 224u8, 155u8, 202u8, 38u8, 110u8, 232u8, 34u8, 50u8, 98u8, 201u8, 26u8, 221u8, 159u8, 147u8, 171u8, 47u8, 125u8, 125u8, 170u8, 98u8, 75u8, 153u8, 165u8, 21u8, 226u8, 200u8, 181u8, 59u8, 37u8, 162u8, 120u8, 153u8, 31u8, 150u8, 134u8, 60u8, 147u8, 165u8, 86u8, 248u8, 53u8, 216u8, 4u8, 185u8, 246u8, 38u8, 164u8, 73u8, 7u8, 80u8, 134u8, 20u8, 43u8, 119u8, 101u8, 140u8, 240u8, 70u8, 159u8, 236u8, 97u8, 249u8, 223u8, 81u8, 191u8, 85u8, 4u8, 170u8, 56u8, 35u8, 183u8, 217u8, 182u8, 140u8, 54u8, 57u8, 237u8, 27u8, 101u8, 123u8, 178u8, 95u8, 169u8, 230u8, 219u8, 16u8, 140u8, 255u8, 12u8, 183u8, 157u8, 46u8, 45u8, 249u8, 126u8, 189u8, 190u8, 40u8, 169u8, 98u8, 36u8, 93u8, 112u8, 32u8, 75u8, 157u8, 3u8, 132u8, 251u8, 41u8, 53u8, 134u8, 124u8, 69u8, 240u8, 171u8, 16u8, 248u8, 132u8, 185u8, 17u8, 152u8, 237u8, 217u8, 200u8, 246u8, 54u8, 93u8, 150u8, 124u8, 60u8, 39u8, 187u8, 188u8, 141u8, 100u8, 55u8, 186u8, 151u8, 151u8, 91u8, 145u8, 6u8, 229u8, 198u8, 38u8, 82u8, 219u8, 102u8, 224u8, 123u8, 151u8, 61u8, 121u8, 129u8, 224u8, 22u8, 53u8, 146u8, 18u8, 190u8, 243u8, 156u8, 113u8, 98u8, 117u8, 143u8, 24u8, 161u8, 1u8, 170u8, 241u8, 237u8, 47u8, 202u8, 195u8, 199u8, 128u8, 254u8, 182u8, 19u8, 11u8, 119u8, 19u8, 253u8, 170u8, 73u8, 177u8, 249u8, 253u8, 131u8, 62u8, 126u8, 31u8, 221u8, 161u8, 67u8, 134u8, 106u8, 35u8, 58u8, 166u8, 32u8, 217u8, 216u8, 168u8, 3u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 165u8, 243u8, 106u8, 227u8, 36u8, 215u8, 177u8, 185u8, 192u8, 144u8, 4u8, 24u8, 137u8, 84u8, 157u8, 226u8, 137u8, 81u8, 71u8, 133u8, 176u8, 2u8, 82u8, 99u8, 102u8, 167u8, 205u8, 54u8, 60u8, 183u8, 154u8, 165u8, 85u8, 131u8, 141u8, 239u8, 143u8, 85u8, 138u8, 35u8, 167u8, 132u8, 185u8, 64u8, 231u8, 18u8, 94u8, 211u8, 101u8, 64u8, 173u8, 83u8, 94u8, 151u8, 207u8, 220u8, 77u8, 235u8, 250u8, 81u8, 223u8, 211u8, 104u8, 145u8, 215u8, 244u8, 122u8, 65u8, 118u8, 47u8, 156u8, 109u8, 71u8, 37u8, 114u8, 98u8, 95u8, 113u8, 199u8, 134u8, 161u8, 152u8, 169u8, 157u8, 104u8, 45u8, 185u8, 148u8, 79u8, 1u8, 219u8, 7u8, 254u8, 136u8, 37u8, 47u8];
        let proof_bytes = vector[180u8, 138u8, 178u8, 155u8, 151u8, 139u8, 244u8, 99u8, 183u8, 37u8, 4u8, 85u8, 235u8, 121u8, 115u8, 235u8, 77u8, 69u8, 203u8, 250u8, 35u8, 11u8, 204u8, 204u8, 14u8, 32u8, 221u8, 215u8, 30u8, 88u8, 81u8, 151u8, 227u8, 112u8, 238u8, 247u8, 125u8, 226u8, 88u8, 23u8, 157u8, 221u8, 55u8, 37u8, 120u8, 220u8, 8u8, 160u8, 204u8, 232u8, 87u8, 243u8, 250u8, 124u8, 66u8, 93u8, 95u8, 10u8, 11u8, 79u8, 246u8, 158u8, 237u8, 28u8, 167u8, 172u8, 205u8, 100u8, 235u8, 144u8, 145u8, 120u8, 131u8, 120u8, 1u8, 187u8, 255u8, 17u8, 176u8, 74u8, 146u8, 69u8, 137u8, 105u8, 206u8, 141u8, 195u8, 156u8, 171u8, 73u8, 236u8, 236u8, 154u8, 51u8, 133u8, 142u8, 253u8, 241u8, 80u8, 101u8, 124u8, 56u8, 172u8, 65u8, 26u8, 224u8, 85u8, 50u8, 95u8, 115u8, 199u8, 64u8, 192u8, 119u8, 125u8, 191u8, 172u8, 102u8, 109u8, 155u8, 192u8, 206u8, 130u8, 131u8, 149u8, 87u8, 167u8, 155u8];
        let public_inputs = vector[137u8, 190u8, 189u8, 224u8, 185u8, 209u8, 74u8, 149u8, 149u8, 207u8, 42u8, 238u8, 208u8, 119u8, 101u8, 45u8, 79u8, 210u8, 221u8, 28u8, 11u8, 190u8, 176u8, 102u8, 242u8, 50u8, 127u8, 41u8, 236u8, 78u8, 200u8, 46u8, 0u8, 225u8, 245u8, 5u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8]; // Wrong public inputs
        
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
        let commitment_bytes = vector[43u8, 97u8, 146u8, 75u8, 219u8, 129u8, 76u8, 224u8, 16u8, 223u8, 222u8, 119u8, 215u8, 155u8, 97u8, 235u8, 172u8, 97u8, 237u8, 243u8, 59u8, 192u8, 136u8, 25u8, 48u8, 115u8, 235u8, 238u8, 57u8, 47u8, 218u8, 11u8]; // Different Poseidon commitment hash (32 bytes)
        let owner = @0x3;
        
        let ctx = test_scenario::ctx(&mut scenario);
        proximity::create_commitment(&server_cap, commitment_bytes, owner, ctx);
        
        test_scenario::return_to_sender(&scenario, server_cap);
    };

    // Verify proximity proof with different valid coordinates within 10km
    scenario.next_tx(@0x3);
    {
        let mut commitment = test_scenario::take_shared<proximity::LocationCommitment>(&scenario);
        let vk_bytes = vector[142u8, 37u8, 216u8, 229u8, 250u8, 242u8, 171u8, 206u8, 84u8, 37u8, 34u8, 116u8, 74u8, 153u8, 143u8, 251u8, 152u8, 121u8, 224u8, 155u8, 202u8, 38u8, 110u8, 232u8, 34u8, 50u8, 98u8, 201u8, 26u8, 221u8, 159u8, 147u8, 171u8, 47u8, 125u8, 125u8, 170u8, 98u8, 75u8, 153u8, 165u8, 21u8, 226u8, 200u8, 181u8, 59u8, 37u8, 162u8, 120u8, 153u8, 31u8, 150u8, 134u8, 60u8, 147u8, 165u8, 86u8, 248u8, 53u8, 216u8, 4u8, 185u8, 246u8, 38u8, 164u8, 73u8, 7u8, 80u8, 134u8, 20u8, 43u8, 119u8, 101u8, 140u8, 240u8, 70u8, 159u8, 236u8, 97u8, 249u8, 223u8, 81u8, 191u8, 85u8, 4u8, 170u8, 56u8, 35u8, 183u8, 217u8, 182u8, 140u8, 54u8, 57u8, 237u8, 27u8, 101u8, 123u8, 178u8, 95u8, 169u8, 230u8, 219u8, 16u8, 140u8, 255u8, 12u8, 183u8, 157u8, 46u8, 45u8, 249u8, 126u8, 189u8, 190u8, 40u8, 169u8, 98u8, 36u8, 93u8, 112u8, 32u8, 75u8, 157u8, 3u8, 132u8, 251u8, 41u8, 53u8, 134u8, 124u8, 69u8, 240u8, 171u8, 16u8, 248u8, 132u8, 185u8, 17u8, 152u8, 237u8, 217u8, 200u8, 246u8, 54u8, 93u8, 150u8, 124u8, 60u8, 39u8, 187u8, 188u8, 141u8, 100u8, 55u8, 186u8, 151u8, 151u8, 91u8, 145u8, 6u8, 229u8, 198u8, 38u8, 82u8, 219u8, 102u8, 224u8, 123u8, 151u8, 61u8, 121u8, 129u8, 224u8, 22u8, 53u8, 146u8, 18u8, 190u8, 243u8, 156u8, 113u8, 98u8, 117u8, 143u8, 24u8, 161u8, 1u8, 170u8, 241u8, 237u8, 47u8, 202u8, 195u8, 199u8, 128u8, 254u8, 182u8, 19u8, 11u8, 119u8, 19u8, 253u8, 170u8, 73u8, 177u8, 249u8, 253u8, 131u8, 62u8, 126u8, 31u8, 221u8, 161u8, 67u8, 134u8, 106u8, 35u8, 58u8, 166u8, 32u8, 217u8, 216u8, 168u8, 3u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 165u8, 243u8, 106u8, 227u8, 36u8, 215u8, 177u8, 185u8, 192u8, 144u8, 4u8, 24u8, 137u8, 84u8, 157u8, 226u8, 137u8, 81u8, 71u8, 133u8, 176u8, 2u8, 82u8, 99u8, 102u8, 167u8, 205u8, 54u8, 60u8, 183u8, 154u8, 165u8, 85u8, 131u8, 141u8, 239u8, 143u8, 85u8, 138u8, 35u8, 167u8, 132u8, 185u8, 64u8, 231u8, 18u8, 94u8, 211u8, 101u8, 64u8, 173u8, 83u8, 94u8, 151u8, 207u8, 220u8, 77u8, 235u8, 250u8, 81u8, 223u8, 211u8, 104u8, 145u8, 215u8, 244u8, 122u8, 65u8, 118u8, 47u8, 156u8, 109u8, 71u8, 37u8, 114u8, 98u8, 95u8, 113u8, 199u8, 134u8, 161u8, 152u8, 169u8, 157u8, 104u8, 45u8, 185u8, 148u8, 79u8, 1u8, 219u8, 7u8, 254u8, 136u8, 37u8, 47u8];
        let proof_bytes = vector[85u8, 186u8, 92u8, 112u8, 47u8, 194u8, 39u8, 164u8, 41u8, 236u8, 138u8, 233u8, 197u8, 84u8, 228u8, 70u8, 228u8, 168u8, 155u8, 5u8, 216u8, 128u8, 193u8, 31u8, 160u8, 98u8, 217u8, 142u8, 44u8, 16u8, 109u8, 143u8, 222u8, 252u8, 167u8, 46u8, 240u8, 143u8, 197u8, 53u8, 25u8, 198u8, 92u8, 111u8, 215u8, 184u8, 45u8, 84u8, 82u8, 181u8, 204u8, 240u8, 217u8, 127u8, 183u8, 236u8, 162u8, 254u8, 166u8, 80u8, 14u8, 143u8, 116u8, 22u8, 66u8, 168u8, 145u8, 215u8, 151u8, 48u8, 134u8, 215u8, 193u8, 85u8, 90u8, 33u8, 34u8, 186u8, 56u8, 87u8, 82u8, 222u8, 183u8, 165u8, 253u8, 57u8, 248u8, 121u8, 119u8, 40u8, 83u8, 167u8, 5u8, 109u8, 14u8, 129u8, 95u8, 173u8, 96u8, 239u8, 146u8, 118u8, 193u8, 105u8, 140u8, 173u8, 35u8, 214u8, 186u8, 64u8, 235u8, 237u8, 27u8, 79u8, 86u8, 141u8, 100u8, 84u8, 129u8, 207u8, 202u8, 190u8, 54u8, 125u8, 12u8, 239u8, 147u8, 43u8];
        let public_inputs = vector[43u8, 97u8, 146u8, 75u8, 219u8, 129u8, 76u8, 224u8, 16u8, 223u8, 222u8, 119u8, 215u8, 155u8, 97u8, 235u8, 172u8, 97u8, 237u8, 243u8, 59u8, 192u8, 136u8, 25u8, 48u8, 115u8, 235u8, 238u8, 57u8, 47u8, 218u8, 11u8, 0u8, 225u8, 245u8, 5u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8];
        
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
        let commitment_bytes = vector[19u8, 157u8, 133u8, 145u8, 35u8, 240u8, 149u8, 206u8, 95u8, 229u8, 71u8, 46u8, 108u8, 7u8, 30u8, 37u8, 112u8, 118u8, 106u8, 107u8, 234u8, 58u8, 207u8, 165u8, 174u8, 62u8, 5u8, 195u8, 143u8, 104u8, 95u8, 22u8]; // Absolute value Poseidon commitment hash (32 bytes)
        let owner = @0x4;
        
        let ctx = test_scenario::ctx(&mut scenario);
        proximity::create_commitment(&server_cap, commitment_bytes, owner, ctx);
        
        test_scenario::return_to_sender(&scenario, server_cap);
    };

    // Verify proximity proof with absolute value coordinates
    scenario.next_tx(@0x4);
    {
        let mut commitment = test_scenario::take_shared<proximity::LocationCommitment>(&scenario);
        let vk_bytes = vector[142u8, 37u8, 216u8, 229u8, 250u8, 242u8, 171u8, 206u8, 84u8, 37u8, 34u8, 116u8, 74u8, 153u8, 143u8, 251u8, 152u8, 121u8, 224u8, 155u8, 202u8, 38u8, 110u8, 232u8, 34u8, 50u8, 98u8, 201u8, 26u8, 221u8, 159u8, 147u8, 171u8, 47u8, 125u8, 125u8, 170u8, 98u8, 75u8, 153u8, 165u8, 21u8, 226u8, 200u8, 181u8, 59u8, 37u8, 162u8, 120u8, 153u8, 31u8, 150u8, 134u8, 60u8, 147u8, 165u8, 86u8, 248u8, 53u8, 216u8, 4u8, 185u8, 246u8, 38u8, 164u8, 73u8, 7u8, 80u8, 134u8, 20u8, 43u8, 119u8, 101u8, 140u8, 240u8, 70u8, 159u8, 236u8, 97u8, 249u8, 223u8, 81u8, 191u8, 85u8, 4u8, 170u8, 56u8, 35u8, 183u8, 217u8, 182u8, 140u8, 54u8, 57u8, 237u8, 27u8, 101u8, 123u8, 178u8, 95u8, 169u8, 230u8, 219u8, 16u8, 140u8, 255u8, 12u8, 183u8, 157u8, 46u8, 45u8, 249u8, 126u8, 189u8, 190u8, 40u8, 169u8, 98u8, 36u8, 93u8, 112u8, 32u8, 75u8, 157u8, 3u8, 132u8, 251u8, 41u8, 53u8, 134u8, 124u8, 69u8, 240u8, 171u8, 16u8, 248u8, 132u8, 185u8, 17u8, 152u8, 237u8, 217u8, 200u8, 246u8, 54u8, 93u8, 150u8, 124u8, 60u8, 39u8, 187u8, 188u8, 141u8, 100u8, 55u8, 186u8, 151u8, 151u8, 91u8, 145u8, 6u8, 229u8, 198u8, 38u8, 82u8, 219u8, 102u8, 224u8, 123u8, 151u8, 61u8, 121u8, 129u8, 224u8, 22u8, 53u8, 146u8, 18u8, 190u8, 243u8, 156u8, 113u8, 98u8, 117u8, 143u8, 24u8, 161u8, 1u8, 170u8, 241u8, 237u8, 47u8, 202u8, 195u8, 199u8, 128u8, 254u8, 182u8, 19u8, 11u8, 119u8, 19u8, 253u8, 170u8, 73u8, 177u8, 249u8, 253u8, 131u8, 62u8, 126u8, 31u8, 221u8, 161u8, 67u8, 134u8, 106u8, 35u8, 58u8, 166u8, 32u8, 217u8, 216u8, 168u8, 3u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 165u8, 243u8, 106u8, 227u8, 36u8, 215u8, 177u8, 185u8, 192u8, 144u8, 4u8, 24u8, 137u8, 84u8, 157u8, 226u8, 137u8, 81u8, 71u8, 133u8, 176u8, 2u8, 82u8, 99u8, 102u8, 167u8, 205u8, 54u8, 60u8, 183u8, 154u8, 165u8, 85u8, 131u8, 141u8, 239u8, 143u8, 85u8, 138u8, 35u8, 167u8, 132u8, 185u8, 64u8, 231u8, 18u8, 94u8, 211u8, 101u8, 64u8, 173u8, 83u8, 94u8, 151u8, 207u8, 220u8, 77u8, 235u8, 250u8, 81u8, 223u8, 211u8, 104u8, 145u8, 215u8, 244u8, 122u8, 65u8, 118u8, 47u8, 156u8, 109u8, 71u8, 37u8, 114u8, 98u8, 95u8, 113u8, 199u8, 134u8, 161u8, 152u8, 169u8, 157u8, 104u8, 45u8, 185u8, 148u8, 79u8, 1u8, 219u8, 7u8, 254u8, 136u8, 37u8, 47u8];
        let proof_bytes = vector[180u8, 138u8, 178u8, 155u8, 151u8, 139u8, 244u8, 99u8, 183u8, 37u8, 4u8, 85u8, 235u8, 121u8, 115u8, 235u8, 77u8, 69u8, 203u8, 250u8, 35u8, 11u8, 204u8, 204u8, 14u8, 32u8, 221u8, 215u8, 30u8, 88u8, 81u8, 151u8, 227u8, 112u8, 238u8, 247u8, 125u8, 226u8, 88u8, 23u8, 157u8, 221u8, 55u8, 37u8, 120u8, 220u8, 8u8, 160u8, 204u8, 232u8, 87u8, 243u8, 250u8, 124u8, 66u8, 93u8, 95u8, 10u8, 11u8, 79u8, 246u8, 158u8, 237u8, 28u8, 167u8, 172u8, 205u8, 100u8, 235u8, 144u8, 145u8, 120u8, 131u8, 120u8, 1u8, 187u8, 255u8, 17u8, 176u8, 74u8, 146u8, 69u8, 137u8, 105u8, 206u8, 141u8, 195u8, 156u8, 171u8, 73u8, 236u8, 236u8, 154u8, 51u8, 133u8, 142u8, 253u8, 241u8, 80u8, 101u8, 124u8, 56u8, 172u8, 65u8, 26u8, 224u8, 85u8, 50u8, 95u8, 115u8, 199u8, 64u8, 192u8, 119u8, 125u8, 191u8, 172u8, 102u8, 109u8, 155u8, 192u8, 206u8, 130u8, 131u8, 149u8, 87u8, 167u8, 155u8];
        let public_inputs = vector[137u8, 190u8, 189u8, 224u8, 185u8, 209u8, 74u8, 149u8, 149u8, 207u8, 42u8, 238u8, 208u8, 119u8, 101u8, 45u8, 176u8, 210u8, 221u8, 28u8, 11u8, 190u8, 176u8, 102u8, 242u8, 50u8, 127u8, 41u8, 236u8, 78u8, 200u8, 46u8, 0u8, 225u8, 245u8, 5u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8];
        
        let ctx = test_scenario::ctx(&mut scenario);
        proximity::verify_proximity_proof(&mut commitment, vk_bytes, proof_bytes, public_inputs, ctx);
        
        // Verify nonce was incremented
        let nonce = proximity::get_nonce(&commitment);
        assert!(nonce == 1, 0);
        
        test_scenario::return_shared(commitment);
    };

    test_scenario::end(scenario);
}
