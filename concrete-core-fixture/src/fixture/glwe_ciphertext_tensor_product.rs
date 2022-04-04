use crate::fixture::Fixture;
use crate::generation::prototyping::{
    PrototypesFloatCleartext, PrototypesGlweCiphertext, PrototypesGlweSecretKey,
    PrototypesPlaintextVector,
};
use crate::generation::synthesizing::{SynthesizesFloatCleartext, SynthesizesGlweCiphertext};
use crate::generation::{IntegerPrecision, Maker, PrecisionF64};
use crate::raw::generation::RawUnsignedIntegers;
use crate::raw::statistical_test::assert_noise_distribution;
use concrete_commons::dispersion::Variance;
use concrete_commons::parameters::{GlweDimension, PolynomialSize};
use concrete_core::prelude::markers::{
    BinaryKeyDistribution, GaussianKeyDistribution, KeyDistributionMarker, TernaryKeyDistribution,
};
use concrete_core::prelude::numeric::UnsignedInteger;
use concrete_core::prelude::{
    BinaryKeyKind, CleartextEntity, DispersionParameter, GaussianKeyKind, GlweCiphertextEntity,
    GlweCiphertextTensorProductEngine, TernaryKeyKind,
};
use std::any::TypeId;

/// A fixture for the types implementing the `GlweCiphertextTensorProductEngine` trait.
pub struct GlweCiphertextTensorProductFixture;

#[derive(Debug)]
pub struct GlweCiphertextTensorProductParameters {
    pub polynomial_size: PolynomialSize,
    pub glwe_dimension: GlweDimension,
    pub noise_glwe_1: Variance,
    pub noise_glwe_2: Variance,
    pub delta_1: f64,
    pub delta_2: f64,
    pub msg_bound_1: f64,
    pub msg_bound_2: f64,
}

impl<Precision, Engine, CiphertextIn1, CiphertextIn2, CiphertextOut, Cleartext>
    Fixture<Precision, Engine, (CiphertextIn1, CiphertextIn2, CiphertextOut, Cleartext)>
    for GlweCiphertextTensorProductFixture
where
    Precision: IntegerPrecision,
    Cleartext: CleartextEntity,
    Engine:
        GlweCiphertextTensorProductEngine<CiphertextIn1, CiphertextIn2, CiphertextOut, Cleartext>,
    CiphertextIn1: GlweCiphertextEntity,
    CiphertextIn2: GlweCiphertextEntity<KeyDistribution = CiphertextIn1::KeyDistribution>,
    CiphertextOut: GlweCiphertextEntity<KeyDistribution = CiphertextIn1::KeyDistribution>,
    Maker: SynthesizesGlweCiphertext<Precision, CiphertextIn1>
        + SynthesizesGlweCiphertext<Precision, CiphertextIn2>
        + SynthesizesGlweCiphertext<Precision, CiphertextOut>
        + SynthesizesFloatCleartext<PrecisionF64, Cleartext>,
{
    type Parameters = GlweCiphertextTensorProductParameters;
    type RepetitionPrototypes = (
        <Maker as PrototypesPlaintextVector<Precision>>::PlaintextVectorProto,
        <Maker as PrototypesPlaintextVector<Precision>>::PlaintextVectorProto,
        <Maker as PrototypesGlweSecretKey<Precision, CiphertextIn1::KeyDistribution>>::GlweSecretKeyProto,
        <Maker as PrototypesFloatCleartext<PrecisionF64>>::CleartextProto,
    );
    type SamplePrototypes =
    (<Maker as PrototypesGlweCiphertext<Precision, CiphertextIn1::KeyDistribution>>::GlweCiphertextProto,
     <Maker as PrototypesGlweCiphertext<Precision,
         CiphertextIn1::KeyDistribution>>::GlweCiphertextProto,
    );

    type PreExecutionContext = (CiphertextIn1, CiphertextIn2, Cleartext);
    type PostExecutionContext = (CiphertextIn1, CiphertextIn2, CiphertextOut, Cleartext);
    type Criteria = (Variance,);
    type Outcome = (Vec<Precision::Raw>, Vec<Precision::Raw>);

    fn generate_parameters_iterator() -> Box<dyn Iterator<Item = Self::Parameters>> {
        Box::new(
            vec![
                GlweCiphertextTensorProductParameters {
                    noise_glwe_1: Variance(0.00000001),
                    noise_glwe_2: Variance(0.00000001),
                    delta_1: 16_f64,
                    delta_2: 16_f64,
                    msg_bound_1: 4_f64,
                    msg_bound_2: 4_f64,
                    glwe_dimension: GlweDimension(200),
                    polynomial_size: PolynomialSize(256),
                },
                GlweCiphertextTensorProductParameters {
                    noise_glwe_1: Variance(0.00000001),
                    noise_glwe_2: Variance(0.00000001),
                    delta_1: 16_f64,
                    delta_2: 16_f64,
                    msg_bound_1: 4_f64,
                    msg_bound_2: 4_f64,
                    glwe_dimension: GlweDimension(1),
                    polynomial_size: PolynomialSize(256),
                },
            ]
            .into_iter(),
        )
    }

    fn generate_random_repetition_prototypes(
        parameters: &Self::Parameters,
        maker: &mut Maker,
    ) -> Self::RepetitionPrototypes {
        let proto_secret_key =
            maker.new_glwe_secret_key(parameters.glwe_dimension, parameters.polynomial_size);
        // TODO make 5 more generic
        let raw_plaintext_vector =
            Precision::Raw::uniform_n_msb_vec(5, parameters.polynomial_size.0);
        let proto_plaintext_vector1 =
            maker.transform_raw_vec_to_plaintext_vector(raw_plaintext_vector.as_slice());
        let raw_plaintext_vector =
            Precision::Raw::uniform_n_msb_vec(5, parameters.polynomial_size.0);
        let proto_plaintext_vector2 =
            maker.transform_raw_vec_to_plaintext_vector(raw_plaintext_vector.as_slice());
        let s = 1_f64;
        let scale = <Maker as PrototypesFloatCleartext<PrecisionF64>>::transform_raw_to_cleartext(
            maker, &s,
        );
        (
            proto_plaintext_vector1,
            proto_plaintext_vector2,
            proto_secret_key,
            scale,
        )
    }

    fn generate_random_sample_prototypes(
        parameters: &Self::Parameters,
        maker: &mut Maker,
        repetition_proto: &Self::RepetitionPrototypes,
    ) -> Self::SamplePrototypes {
        let (proto_plaintext_vector1, proto_plaintext_vector2, proto_secret_key, _) =
            repetition_proto;
        let proto_ciphertext1 = maker.encrypt_plaintext_vector_to_glwe_ciphertext(
            proto_secret_key,
            &proto_plaintext_vector1,
            parameters.noise_glwe_1,
        );
        let proto_ciphertext2 = maker.encrypt_plaintext_vector_to_glwe_ciphertext(
            proto_secret_key,
            &proto_plaintext_vector2,
            parameters.noise_glwe_2,
        );
        (proto_ciphertext1, proto_ciphertext2)
    }

    fn prepare_context(
        _parameters: &Self::Parameters,
        maker: &mut Maker,
        // clippy convention: this variable will not be used (_varname)
        repetition_proto: &Self::RepetitionPrototypes,
        sample_proto: &Self::SamplePrototypes,
    ) -> Self::PreExecutionContext {
        let (_, _, _, proto_scale) = repetition_proto;
        let (proto_ciphertext1, proto_ciphertext2) = sample_proto;
        let ciphertext1 = maker.synthesize_glwe_ciphertext(proto_ciphertext1);
        let ciphertext2 = maker.synthesize_glwe_ciphertext(proto_ciphertext2);
        let scale =
            <Maker as SynthesizesFloatCleartext<PrecisionF64, Cleartext>>::synthesize_cleartext(
                maker,
                proto_scale,
            );

        // TODO: we need to update scale to use the correct value
        (ciphertext1, ciphertext2, scale)
    }

    fn execute_engine(
        _parameters: &Self::Parameters,
        engine: &mut Engine,
        context: Self::PreExecutionContext,
    ) -> Self::PostExecutionContext {
        let (proto_ciphertext1, proto_ciphertext2, scale) = context;
        let output_ciphertext = unsafe {
            engine.tensor_product_glwe_ciphertext_unchecked(
                &proto_ciphertext1,
                &proto_ciphertext2,
                &scale,
            )
        };
        (
            proto_ciphertext1,
            proto_ciphertext2,
            output_ciphertext,
            scale,
        )
    }

    fn process_context(
        parameters: &Self::Parameters,
        maker: &mut Maker,
        repetition_proto: &Self::RepetitionPrototypes,
        _sample_proto: &Self::SamplePrototypes,
        context: Self::PostExecutionContext,
    ) -> Self::Outcome {
        let (proto_plaintext_vector1, proto_plaintext_vector2, proto_secret_key, proto_scale) =
            repetition_proto;
        let (input_ciphertext_1, input_ciphertext_2, output_ciphertext, scale) = context;

        let proto_output_ciphertext = maker.unsynthesize_glwe_ciphertext(&output_ciphertext);

        maker.destroy_glwe_ciphertext(input_ciphertext_1);
        maker.destroy_glwe_ciphertext(input_ciphertext_2);
        maker.destroy_glwe_ciphertext(output_ciphertext);
        <Maker as SynthesizesFloatCleartext<PrecisionF64, Cleartext>>::destroy_cleartext(
            maker, scale,
        );

        let proto_output_plaintext_vector = maker.decrypt_glwe_ciphertext_to_plaintext_vector(
            proto_secret_key,
            &proto_output_ciphertext,
        );

        let raw_input_plaintext_vector1 =
            maker.transform_plaintext_vector_to_raw_vec(proto_plaintext_vector1);
        let raw_input_plaintext_vector2 =
            maker.transform_plaintext_vector_to_raw_vec(proto_plaintext_vector2);
        let raw_scale =
            <Maker as PrototypesFloatCleartext<PrecisionF64>>::transform_cleartext_to_raw(
                maker,
                &proto_scale,
            );

        // we are checking noise vals
        // we need to compute the values in the plaintext domain
        // make a tensor product between two plaintext vectors in 163-167 to compute this
        // change to tensor prod size
        let mut raw_input_plaintext_vector = Vec::with_capacity(parameters.polynomial_size.0);

        //maker
        //.transform_plaintext_vector_to_raw_vec(proto_input_plaintext_vector1)
        //.into_iter()
        //.map(|v| v * raw_input_plaintext_vector1)
        //.collect();
        (
            //correct
            raw_input_plaintext_vector,
            maker.transform_plaintext_vector_to_raw_vec(&proto_output_plaintext_vector),
        )
    }

    fn compute_criteria(
        parameters: &Self::Parameters,
        _maker: &mut Maker,
        _repetition_proto: &Self::RepetitionPrototypes,
    ) -> Self::Criteria {
        let output_variance = fix_estimate_tensor_product_noise::<
            Precision::Raw,
            Variance,
            Variance,
            CiphertextIn1::KeyDistribution,
        >(
            parameters.polynomial_size,
            parameters.glwe_dimension,
            parameters.noise_glwe_1,
            parameters.noise_glwe_2,
            parameters.delta_1,
            parameters.delta_2,
            parameters.msg_bound_1,
            parameters.msg_bound_2,
        );
        (output_variance,)
    }

    fn verify(criteria: &Self::Criteria, outputs: &[Self::Outcome]) -> bool {
        //correct
        let (means, actual): (Vec<_>, Vec<_>) = outputs.iter().cloned().unzip();
        // pt without an error
        let means: Vec<Precision::Raw> = means.into_iter().flatten().collect();
        // what we get from decryption
        let actual: Vec<Precision::Raw> = actual.into_iter().flatten().collect();
        assert_noise_distribution(&actual, means.as_slice(), criteria.0)
    }
}

// FIXME:
// The current NPE does not use the key distribution markers of concrete-core. This function makes
// the mapping. This function should be removed as soon as the npe uses the types of concrete-core.

fn fix_estimate_tensor_product_noise<T, D1, D2, K>(
    poly_size: PolynomialSize,
    rlwe_mask_size: GlweDimension,
    var_glwe1: D1,
    var_glwe2: D2,
    delta_1: f64,
    delta_2: f64,
    max_msg_1: f64,
    max_msg_2: f64,
) -> Variance
where
    T: UnsignedInteger,
    D1: DispersionParameter,
    D2: DispersionParameter,
    K: KeyDistributionMarker,
{
    let k_type_id = TypeId::of::<K>();
    if k_type_id == TypeId::of::<BinaryKeyDistribution>() {
        concrete_npe::estimate_tensor_product_noise::<T, D1, D2, BinaryKeyKind>(
            poly_size,
            rlwe_mask_size,
            var_glwe1,
            var_glwe2,
            delta_1,
            delta_2,
            max_msg_1,
            max_msg_2,
        )
    } else if k_type_id == TypeId::of::<TernaryKeyDistribution>() {
        concrete_npe::estimate_tensor_product_noise::<T, D1, D2, TernaryKeyKind>(
            poly_size,
            rlwe_mask_size,
            var_glwe1,
            var_glwe2,
            delta_1,
            delta_2,
            max_msg_1,
            max_msg_2,
        )
    } else if k_type_id == TypeId::of::<GaussianKeyDistribution>() {
        concrete_npe::estimate_tensor_product_noise::<T, D1, D2, GaussianKeyKind>(
            poly_size,
            rlwe_mask_size,
            var_glwe1,
            var_glwe2,
            delta_1,
            delta_2,
            max_msg_1,
            max_msg_2,
        )
    } else {
        panic!("Unknown key distribution encountered.")
    }
}