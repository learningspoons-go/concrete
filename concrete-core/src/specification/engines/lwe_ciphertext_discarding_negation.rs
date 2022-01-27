use super::engine_error;
use crate::specification::engines::AbstractEngine;
use crate::specification::entities::LweCiphertextEntity;

engine_error! {
    LweCiphertextDiscardingNegationError for LweCiphertextDiscardingNegationEngine @
    LweDimensionMismatch => "The input and output LWE dimension must be the same."
}

impl<EngineError: std::error::Error> LweCiphertextDiscardingNegationError<EngineError> {
    /// Validates the inputs
    pub fn perform_generic_checks<InputCiphertext, OutputCiphertext>(
        output: &OutputCiphertext,
        input: &InputCiphertext,
    ) -> Result<(), Self>
    where
        InputCiphertext: LweCiphertextEntity,
        OutputCiphertext: LweCiphertextEntity<KeyDistribution = InputCiphertext::KeyDistribution>,
    {
        if input.lwe_dimension() != output.lwe_dimension() {
            return Err(Self::LweDimensionMismatch);
        }

        Ok(())
    }
}

/// A trait for engines negating (discarding) LWE ciphertexts.
///
/// # Semantics
///
/// This [discarding](super#operation-semantics) operation fills the `output` LWE ciphertext with
/// the negation of the `input` LWE ciphertext.
///
/// # Formal Definition
///
/// ## LWE negation
///
/// It is a specification of the GLWE negation described below.
///
/// ## GLWE negation
///
/// It is easy to compute the opposite of a [`GLWE ciphertext`](`GlweCiphertextEntity`), i.e., a
/// GLWE ciphertext encrypting the opposite of the encrypted plaintext. Let a GLWE ciphertext
/// $$
/// \mathsf{CT} = \left( \vec{A}, B\right) \in \mathsf{GLWE}_{\vec{S}} \left( \mathsf{PT} \right)
/// \subseteq \mathcal{R}_q^{k+1} $$
/// encrypted under the [`GLWE secret key`](`GlweSecretKeyEntity`) $\vec{S} \in \mathcal{R}_q^k$.
/// We can compute the opposite of this GLWE ciphertext and obtain as a result a new GLWE ciphertext
/// encrypting the opposite of the plaintext $- \mathsf{PT}$.
///
/// ###### inputs:
/// - $\mathsf{CT} = \left( \vec{A}, B\right) \in \mathsf{GLWE}_{\vec{S}} \left( \mathsf{PT} \right)
///   \subseteq \mathcal{R}_q^{k+1}$: a GLWE ciphertext
///
/// ###### outputs:
/// - $\mathsf{CT}' = \left( \vec{A}' , B' \right) \in \mathsf{GLWE}_{\vec{S}}( -\mathsf{PT}
///   )\subseteq \mathcal{R}_q^{k+1}$: an GLWE ciphertext
///
/// ###### algorithm:
/// 1. Compute $\vec{A}' = -\vec{A} \in\mathcal{R}^k_q$
/// 2. Compute $B' = -B \in\mathcal{R}_q$
/// 3. Output $\left( \vec{A} , B \right)$
pub trait LweCiphertextDiscardingNegationEngine<InputCiphertext, OutputCiphertext>:
    AbstractEngine
where
    InputCiphertext: LweCiphertextEntity,
    OutputCiphertext: LweCiphertextEntity<KeyDistribution = InputCiphertext::KeyDistribution>,
{
    /// Negates an LWE ciphertext.
    fn discard_neg_lwe_ciphertext(
        &mut self,
        output: &mut OutputCiphertext,
        input: &InputCiphertext,
    ) -> Result<(), LweCiphertextDiscardingNegationError<Self::EngineError>>;

    /// Unsafely negates an LWE ciphertext.
    ///
    /// # Safety
    /// For the _general_ safety concerns regarding this operation, refer to the different variants
    /// of [`LweCiphertextDiscardingNegationError`]. For safety concerns _specific_ to an engine,
    /// refer to the implementer safety section.
    unsafe fn discard_neg_lwe_ciphertext_unchecked(
        &mut self,
        output: &mut OutputCiphertext,
        input: &InputCiphertext,
    );
}
