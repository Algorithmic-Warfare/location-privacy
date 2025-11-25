#[test_only]
module location_addr::location_tests;

use location_addr::proximity;

#[test]
fun test_e2e_proximity_verification() {
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
        let commitment_bytes = vector[226u8, 111u8, 186u8, 19u8, 130u8, 33u8, 2u8, 87u8, 208u8, 19u8, 99u8, 17u8, 44u8, 223u8, 22u8, 250u8, 234u8, 161u8, 81u8, 61u8, 176u8, 141u8, 224u8, 148u8, 255u8, 93u8, 221u8, 89u8, 194u8, 123u8, 248u8, 2u8];
        let owner = @0x2;

        let ctx = test_scenario::ctx(&mut scenario);
        proximity::create_commitment(&server_cap, commitment_bytes, owner, ctx);

        test_scenario::return_to_sender(&scenario, server_cap);
    };

    // Verify proximity proof
    scenario.next_tx(@0x2);
    {
        let mut commitment = test_scenario::take_shared<proximity::LocationCommitment>(&scenario);
        let vk_bytes = vector[149u8, 169u8, 253u8, 52u8, 65u8, 67u8, 159u8, 129u8, 154u8, 222u8, 151u8, 28u8, 254u8, 212u8, 22u8, 170u8, 254u8, 178u8, 49u8, 240u8, 29u8, 234u8, 126u8, 127u8, 30u8, 193u8, 192u8, 127u8, 239u8, 26u8, 49u8, 17u8, 221u8, 97u8, 152u8, 213u8, 19u8, 162u8, 233u8, 183u8, 62u8, 21u8, 115u8, 197u8, 125u8, 53u8, 26u8, 183u8, 125u8, 205u8, 221u8, 5u8, 92u8, 208u8, 221u8, 123u8, 220u8, 18u8, 187u8, 84u8, 252u8, 117u8, 114u8, 44u8, 245u8, 76u8, 105u8, 240u8, 150u8, 53u8, 87u8, 18u8, 219u8, 79u8, 194u8, 145u8, 8u8, 225u8, 52u8, 243u8, 205u8, 7u8, 20u8, 56u8, 7u8, 156u8, 173u8, 71u8, 50u8, 101u8, 189u8, 157u8, 64u8, 148u8, 224u8, 34u8, 33u8, 103u8, 183u8, 48u8, 80u8, 8u8, 182u8, 156u8, 181u8, 123u8, 150u8, 138u8, 87u8, 118u8, 80u8, 96u8, 234u8, 248u8, 81u8, 231u8, 228u8, 246u8, 103u8, 51u8, 213u8, 143u8, 147u8, 55u8, 248u8, 79u8, 131u8, 7u8, 199u8, 167u8, 168u8, 60u8, 193u8, 24u8, 250u8, 95u8, 84u8, 76u8, 191u8, 159u8, 159u8, 229u8, 245u8, 56u8, 124u8, 159u8, 169u8, 255u8, 226u8, 152u8, 125u8, 45u8, 241u8, 63u8, 34u8, 200u8, 136u8, 158u8, 8u8, 133u8, 155u8, 89u8, 183u8, 64u8, 192u8, 27u8, 8u8, 137u8, 124u8, 23u8, 189u8, 186u8, 19u8, 12u8, 47u8, 158u8, 241u8, 190u8, 67u8, 185u8, 42u8, 210u8, 37u8, 136u8, 162u8, 147u8, 65u8, 192u8, 76u8, 209u8, 150u8, 2u8, 54u8, 68u8, 253u8, 20u8, 169u8, 40u8, 218u8, 101u8, 105u8, 116u8, 158u8, 71u8, 151u8, 204u8, 59u8, 71u8, 134u8, 98u8, 90u8, 225u8, 14u8, 158u8, 4u8, 81u8, 206u8, 61u8, 165u8, 231u8, 12u8, 21u8, 128u8, 46u8, 2u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 211u8, 235u8, 209u8, 112u8, 97u8, 98u8, 174u8, 129u8, 126u8, 208u8, 111u8, 123u8, 122u8, 39u8, 26u8, 107u8, 214u8, 21u8, 192u8, 207u8, 168u8, 161u8, 61u8, 105u8, 201u8, 223u8, 225u8, 11u8, 244u8, 85u8, 149u8, 10u8, 44u8, 215u8, 73u8, 165u8, 247u8, 243u8, 94u8, 20u8, 99u8, 78u8, 68u8, 209u8, 225u8, 147u8, 124u8, 117u8, 52u8, 158u8, 193u8, 79u8, 210u8, 17u8, 164u8, 99u8, 130u8, 195u8, 3u8, 33u8, 144u8, 175u8, 0u8, 137u8];
        let proof_bytes = vector[12u8, 160u8, 42u8, 39u8, 25u8, 198u8, 237u8, 86u8, 8u8, 176u8, 14u8, 235u8, 198u8, 131u8, 228u8, 87u8, 224u8, 52u8, 49u8, 231u8, 175u8, 75u8, 223u8, 229u8, 219u8, 252u8, 238u8, 64u8, 159u8, 18u8, 208u8, 28u8, 130u8, 194u8, 99u8, 130u8, 40u8, 147u8, 151u8, 47u8, 47u8, 21u8, 56u8, 225u8, 23u8, 96u8, 9u8, 221u8, 252u8, 77u8, 180u8, 252u8, 224u8, 249u8, 155u8, 76u8, 12u8, 126u8, 253u8, 104u8, 39u8, 120u8, 218u8, 39u8, 70u8, 211u8, 134u8, 158u8, 168u8, 17u8, 99u8, 32u8, 33u8, 203u8, 224u8, 2u8, 84u8, 20u8, 122u8, 191u8, 60u8, 125u8, 159u8, 174u8, 153u8, 184u8, 180u8, 129u8, 16u8, 64u8, 189u8, 232u8, 164u8, 79u8, 48u8, 151u8, 10u8, 64u8, 203u8, 248u8, 189u8, 186u8, 107u8, 78u8, 199u8, 78u8, 113u8, 180u8, 143u8, 108u8, 110u8, 230u8, 179u8, 253u8, 42u8, 87u8, 108u8, 104u8, 88u8, 194u8, 2u8, 42u8, 56u8, 236u8, 69u8, 243u8, 102u8, 5u8];
        let public_inputs = vector[226u8, 111u8, 186u8, 19u8, 130u8, 33u8, 2u8, 87u8, 208u8, 19u8, 99u8, 17u8, 44u8, 223u8, 22u8, 250u8, 234u8, 161u8, 81u8, 61u8, 176u8, 141u8, 224u8, 148u8, 255u8, 93u8, 221u8, 89u8, 194u8, 123u8, 248u8, 2u8];

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
fun test_invalid_blinding_factor_fails() {
    use sui::test_scenario;

    let mut scenario = test_scenario::begin(@0x1);
    {
        let ctx = test_scenario::ctx(&mut scenario);
        proximity::init_for_testing(ctx);
    };

    // Create commitment with wrong blinding factor
    scenario.next_tx(@0x1);
    {
        let server_cap = test_scenario::take_from_sender<proximity::ServerCap>(&scenario);
        let commitment_bytes = vector[0u8, 41u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8]; // Wrong commitment bytes
        let owner = @0x2;

        let ctx = test_scenario::ctx(&mut scenario);
        proximity::create_commitment(&server_cap, commitment_bytes, owner, ctx);

        test_scenario::return_to_sender(&scenario, server_cap);
    };

    // Try to verify with valid proof but wrong commitment - should fail
    scenario.next_tx(@0x2);
    {
        let mut commitment = test_scenario::take_shared<proximity::LocationCommitment>(&scenario);
        let vk_bytes = vector[31u8, 149u8, 133u8, 249u8, 33u8, 213u8, 253u8, 57u8, 85u8, 20u8, 178u8, 122u8, 41u8, 234u8, 11u8, 186u8, 109u8, 8u8, 79u8, 210u8, 251u8, 69u8, 86u8, 33u8, 244u8, 191u8, 9u8, 13u8, 1u8, 221u8, 88u8, 175u8, 10u8, 171u8, 65u8, 37u8, 66u8, 14u8, 210u8, 62u8, 166u8, 20u8, 105u8, 130u8, 62u8, 79u8, 155u8, 74u8, 42u8, 218u8, 128u8, 168u8, 57u8, 134u8, 96u8, 227u8, 65u8, 242u8, 71u8, 88u8, 156u8, 190u8, 215u8, 29u8, 174u8, 123u8, 101u8, 224u8, 170u8, 116u8, 72u8, 184u8, 184u8, 39u8, 170u8, 75u8, 62u8, 104u8, 96u8, 241u8, 242u8, 249u8, 68u8, 229u8, 165u8, 235u8, 104u8, 90u8, 82u8, 152u8, 122u8, 212u8, 32u8, 79u8, 118u8, 163u8, 162u8, 233u8, 156u8, 217u8, 172u8, 25u8, 83u8, 231u8, 244u8, 227u8, 91u8, 77u8, 134u8, 232u8, 159u8, 100u8, 151u8, 219u8, 116u8, 244u8, 26u8, 80u8, 121u8, 231u8, 121u8, 237u8, 19u8, 127u8, 159u8, 63u8, 33u8, 22u8, 132u8, 250u8, 25u8, 145u8, 236u8, 224u8, 23u8, 25u8, 92u8, 45u8, 234u8, 75u8, 147u8, 254u8, 226u8, 218u8, 152u8, 130u8, 128u8, 124u8, 2u8, 8u8, 150u8, 46u8, 69u8, 120u8, 225u8, 74u8, 67u8, 178u8, 191u8, 139u8, 252u8, 155u8, 231u8, 106u8, 154u8, 3u8, 28u8, 9u8, 111u8, 218u8, 242u8, 244u8, 153u8, 79u8, 108u8, 50u8, 39u8, 227u8, 103u8, 240u8, 29u8, 76u8, 75u8, 84u8, 130u8, 201u8, 28u8, 222u8, 188u8, 178u8, 146u8, 43u8, 140u8, 94u8, 5u8, 126u8, 71u8, 53u8, 237u8, 74u8, 49u8, 172u8, 228u8, 155u8, 229u8, 64u8, 46u8, 82u8, 161u8, 14u8, 250u8, 42u8, 241u8, 5u8, 224u8, 58u8, 103u8, 86u8, 210u8, 10u8, 236u8, 122u8, 42u8, 163u8, 2u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 182u8, 152u8, 102u8, 154u8, 185u8, 23u8, 168u8, 137u8, 255u8, 21u8, 47u8, 118u8, 85u8, 229u8, 121u8, 106u8, 151u8, 20u8, 162u8, 113u8, 148u8, 4u8, 153u8, 22u8, 50u8, 205u8, 67u8, 64u8, 1u8, 254u8, 31u8, 139u8, 116u8, 243u8, 147u8, 223u8, 79u8, 11u8, 128u8, 73u8, 152u8, 253u8, 225u8, 82u8, 146u8, 142u8, 57u8, 58u8, 239u8, 211u8, 88u8, 52u8, 116u8, 166u8, 231u8, 15u8, 153u8, 52u8, 144u8, 178u8, 90u8, 233u8, 197u8, 135u8];
        let proof_bytes = vector[15u8, 222u8, 135u8, 252u8, 195u8, 3u8, 32u8, 105u8, 103u8, 243u8, 112u8, 73u8, 252u8, 97u8, 179u8, 172u8, 242u8, 103u8, 3u8, 199u8, 8u8, 98u8, 176u8, 48u8, 216u8, 109u8, 117u8, 73u8, 180u8, 108u8, 5u8, 5u8, 14u8, 78u8, 187u8, 21u8, 45u8, 226u8, 33u8, 25u8, 160u8, 225u8, 112u8, 87u8, 249u8, 128u8, 205u8, 246u8, 133u8, 173u8, 154u8, 59u8, 185u8, 67u8, 188u8, 3u8, 79u8, 217u8, 33u8, 93u8, 93u8, 165u8, 223u8, 38u8, 96u8, 80u8, 205u8, 31u8, 51u8, 185u8, 243u8, 223u8, 126u8, 67u8, 100u8, 99u8, 255u8, 181u8, 239u8, 108u8, 222u8, 24u8, 53u8, 126u8, 247u8, 165u8, 250u8, 91u8, 136u8, 205u8, 58u8, 172u8, 5u8, 6u8, 20u8, 29u8, 76u8, 188u8, 193u8, 163u8, 162u8, 199u8, 222u8, 128u8, 117u8, 224u8, 179u8, 160u8, 24u8, 218u8, 115u8, 65u8, 211u8, 49u8, 0u8, 162u8, 180u8, 38u8, 175u8, 41u8, 22u8, 66u8, 213u8, 19u8, 85u8, 29u8, 103u8, 147u8];
        let public_inputs = vector[135u8, 119u8, 189u8, 78u8, 49u8, 203u8, 181u8, 10u8, 163u8, 224u8, 173u8, 125u8, 241u8, 7u8, 97u8, 65u8, 8u8, 97u8, 13u8, 129u8, 74u8, 89u8, 170u8, 52u8, 239u8, 137u8, 141u8, 45u8, 205u8, 206u8, 70u8, 23u8];

        let ctx = test_scenario::ctx(&mut scenario);
        // This should fail because the commitment doesn't match the proof
        proximity::verify_proximity_proof(&mut commitment, vk_bytes, proof_bytes, public_inputs, ctx);

        test_scenario::return_shared(commitment);
    };

    test_scenario::end(scenario);
}

#[test]
#[expected_failure]
fun test_distance_too_high_fails() {
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
        let commitment_bytes = vector[121u8, 132u8, 92u8, 155u8, 186u8, 184u8, 91u8, 56u8, 11u8, 224u8, 68u8, 129u8, 133u8, 32u8, 235u8, 177u8, 115u8, 237u8, 219u8, 44u8, 1u8, 235u8, 215u8, 114u8, 170u8, 1u8, 42u8, 24u8, 39u8, 173u8, 68u8, 26u8];
        let owner = @0x2;

        let ctx = test_scenario::ctx(&mut scenario);
        proximity::create_commitment(&server_cap, commitment_bytes, owner, ctx);

        test_scenario::return_to_sender(&scenario, server_cap);
    };

    // Try to verify with player too far - should fail
    scenario.next_tx(@0x2);
    {
        let mut commitment = test_scenario::take_shared<proximity::LocationCommitment>(&scenario);
        let vk_bytes = vector[31u8, 149u8, 133u8, 249u8, 33u8, 213u8, 253u8, 57u8, 85u8, 20u8, 178u8, 122u8, 41u8, 234u8, 11u8, 186u8, 109u8, 8u8, 79u8, 210u8, 251u8, 69u8, 86u8, 33u8, 244u8, 191u8, 9u8, 13u8, 1u8, 221u8, 88u8, 175u8, 10u8, 171u8, 65u8, 37u8, 66u8, 14u8, 210u8, 62u8, 166u8, 20u8, 105u8, 130u8, 62u8, 79u8, 155u8, 74u8, 42u8, 218u8, 128u8, 168u8, 57u8, 134u8, 96u8, 227u8, 65u8, 242u8, 71u8, 88u8, 156u8, 190u8, 215u8, 29u8, 174u8, 123u8, 101u8, 224u8, 170u8, 116u8, 72u8, 184u8, 184u8, 39u8, 170u8, 75u8, 62u8, 104u8, 96u8, 241u8, 242u8, 249u8, 68u8, 229u8, 165u8, 235u8, 104u8, 90u8, 82u8, 152u8, 122u8, 212u8, 32u8, 79u8, 118u8, 163u8, 162u8, 233u8, 156u8, 217u8, 172u8, 25u8, 83u8, 231u8, 244u8, 227u8, 91u8, 77u8, 134u8, 232u8, 159u8, 100u8, 151u8, 219u8, 116u8, 244u8, 26u8, 80u8, 121u8, 231u8, 121u8, 237u8, 19u8, 127u8, 159u8, 63u8, 33u8, 22u8, 132u8, 250u8, 25u8, 145u8, 236u8, 224u8, 23u8, 25u8, 92u8, 45u8, 234u8, 75u8, 147u8, 254u8, 226u8, 218u8, 152u8, 130u8, 128u8, 124u8, 2u8, 8u8, 150u8, 46u8, 69u8, 120u8, 225u8, 74u8, 67u8, 178u8, 191u8, 139u8, 252u8, 155u8, 231u8, 106u8, 154u8, 3u8, 28u8, 9u8, 111u8, 218u8, 242u8, 244u8, 153u8, 79u8, 108u8, 50u8, 39u8, 227u8, 103u8, 240u8, 29u8, 76u8, 75u8, 84u8, 130u8, 201u8, 28u8, 222u8, 188u8, 178u8, 146u8, 43u8, 140u8, 94u8, 5u8, 126u8, 71u8, 53u8, 237u8, 74u8, 49u8, 172u8, 228u8, 155u8, 229u8, 64u8, 46u8, 82u8, 161u8, 14u8, 250u8, 42u8, 241u8, 5u8, 224u8, 58u8, 103u8, 86u8, 210u8, 10u8, 236u8, 122u8, 42u8, 163u8, 2u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 182u8, 152u8, 102u8, 154u8, 185u8, 23u8, 168u8, 137u8, 255u8, 21u8, 47u8, 118u8, 85u8, 229u8, 121u8, 106u8, 151u8, 20u8, 162u8, 113u8, 148u8, 4u8, 153u8, 22u8, 50u8, 205u8, 67u8, 64u8, 1u8, 254u8, 31u8, 139u8, 116u8, 243u8, 147u8, 223u8, 79u8, 11u8, 128u8, 73u8, 152u8, 253u8, 225u8, 82u8, 146u8, 142u8, 57u8, 58u8, 239u8, 211u8, 88u8, 52u8, 116u8, 166u8, 231u8, 15u8, 153u8, 52u8, 144u8, 178u8, 90u8, 233u8, 197u8, 135u8];
        let proof_bytes = vector[161u8, 2u8, 200u8, 102u8, 249u8, 211u8, 167u8, 38u8, 85u8, 61u8, 132u8, 117u8, 93u8, 79u8, 39u8, 49u8, 82u8, 217u8, 156u8, 178u8, 74u8, 113u8, 60u8, 181u8, 158u8, 145u8, 252u8, 34u8, 168u8, 163u8, 164u8, 30u8, 127u8, 227u8, 208u8, 202u8, 61u8, 214u8, 234u8, 193u8, 118u8, 168u8, 254u8, 14u8, 45u8, 126u8, 23u8, 190u8, 142u8, 82u8, 130u8, 57u8, 3u8, 87u8, 237u8, 42u8, 193u8, 130u8, 19u8, 171u8, 168u8, 142u8, 18u8, 44u8, 233u8, 161u8, 34u8, 222u8, 159u8, 221u8, 223u8, 152u8, 6u8, 168u8, 108u8, 2u8, 250u8, 142u8, 66u8, 183u8, 91u8, 250u8, 179u8, 84u8, 56u8, 135u8, 175u8, 174u8, 7u8, 255u8, 81u8, 84u8, 212u8, 25u8, 34u8, 137u8, 133u8, 210u8, 111u8, 167u8, 167u8, 224u8, 102u8, 41u8, 39u8, 209u8, 222u8, 208u8, 31u8, 124u8, 99u8, 184u8, 213u8, 254u8, 44u8, 95u8, 62u8, 47u8, 115u8, 139u8, 143u8, 230u8, 71u8, 57u8, 150u8, 58u8, 234u8, 28u8];
        let public_inputs = vector[121u8, 132u8, 92u8, 155u8, 186u8, 184u8, 91u8, 56u8, 11u8, 224u8, 68u8, 129u8, 133u8, 32u8, 235u8, 177u8, 115u8, 237u8, 219u8, 44u8, 1u8, 235u8, 215u8, 114u8, 170u8, 1u8, 42u8, 24u8, 39u8, 173u8, 68u8, 26u8];

        let ctx = test_scenario::ctx(&mut scenario);
        // This should fail because the player is too far from the target location
        proximity::verify_proximity_proof(&mut commitment, vk_bytes, proof_bytes, public_inputs, ctx);

        test_scenario::return_shared(commitment);
    };

    test_scenario::end(scenario);
}
