use super::engine_error;
use crate::specification::engines::AbstractEngine;

use crate::specification::entities::{LweCiphertextEntity, LweKeyswitchKeyEntity};

engine_error! {
    LweCiphertextDiscardingKeyswitchError for LweCiphertextDiscardingKeyswitchEngine @
    InputLweDimensionMismatch => "The input ciphertext LWE dimension and keyswitch key input LWE \
                                  dimensions must be the same.",
    OutputLweDimensionMismatch => "The output ciphertext LWE dimension and keyswitch output LWE \
                                   dimensions must be the same."
}

impl<EngineError: std::error::Error> LweCiphertextDiscardingKeyswitchError<EngineError> {
    /// Validates the inputs
    pub fn perform_generic_checks<KeyswitchKey, InputCiphertext, OutputCiphertext>(
        output: &OutputCiphertext,
        input: &InputCiphertext,
        ksk: &KeyswitchKey,
    ) -> Result<(), Self>
    where
        KeyswitchKey: LweKeyswitchKeyEntity,
        InputCiphertext: LweCiphertextEntity<KeyDistribution = KeyswitchKey::InputKeyDistribution>,
        OutputCiphertext:
            LweCiphertextEntity<KeyDistribution = KeyswitchKey::OutputKeyDistribution>,
    {
        if input.lwe_dimension() != ksk.input_lwe_dimension() {
            return Err(Self::InputLweDimensionMismatch);
        }
        if output.lwe_dimension() != ksk.output_lwe_dimension() {
            return Err(Self::OutputLweDimensionMismatch);
        }
        Ok(())
    }
}

/// A trait for engines keyswitching (discarding) LWE ciphertexts.
///
/// # Semantics
///
/// This [discarding](super#operation-semantics) operation fills the `output` LWE ciphertext with
/// the keyswitch of the `input` LWE ciphertext, using the `ksk` LWE keyswitch key.
///
/// # Formal Definition
///
/// ## LWE Keyswitch
///
/// This homomorphic procedure transforms an input [`LWE ciphertext`](`LweCiphertextEntity`)
/// $\mathsf{ct}_{\mathsf{in}} = \left( \vec{a}_{\mathsf{in}} , b_{\mathsf{in}}\right) \in
/// \mathsf{LWE}^{n_{\mathsf{in}}}_{\vec{s}_{\mathsf{in}}}( \mathsf{pt} ) \subseteq
/// \mathbb{Z}_q^{(n_{\mathsf{in}}+1)}$ into an output [`LWE
/// ciphertext`](`LweCiphertextEntity`)$\mathsf{ct}_{\mathsf{out}} = \left( \vec{a}_{\mathsf{out}} ,
/// b_{\mathsf{out}}\right) \in \mathsf{LWE}^{n_{\mathsf{out}}}_{\vec{s}_{\mathsf{out}}}(
/// \mathsf{pt} )\subseteq \mathbb{Z}_q^{(n_{\mathsf{out}}+1)}$ where $n_{\mathsf{in}} =
/// |\vec{s}_{\mathsf{in}}|$ and $n_{\mathsf{out}} = |\vec{s}_{\mathsf{out}}|$. It requires a [`key
/// switching key`](`LweKeyswitchKeyEntity`). The input ciphertext is encrypted under the [`LWE
/// secret key`](`LweSecretKeyEntity`) $\vec{s}_{\mathsf{in}}$ and the output ciphertext is
/// encrypted under the [`LWE secret key`](`LweSecretKeyEntity`) $\vec{s}_{\mathsf{out}}$.
///
/// $$\mathsf{ct}_{\mathsf{in}} \in \mathsf{LWE}^{n_{\mathsf{in}}}_{\vec{s}_{\mathsf{in}}}(
/// \mathsf{pt} ) ~~~~~~~~~~\mathsf{KSK}_{\vec{s}_{\mathsf{in}}\rightarrow \vec{s}_{\mathsf{out}}}$$
/// $$ \mathsf{keyswitch}\left(\mathsf{ct}_{\mathsf{in}} , \mathsf{KSK} \right) \rightarrow
/// \mathsf{ct}_{\mathsf{out}} \in \mathsf{LWE}^{n_{\mathsf{out}}}_{\vec{s}_{\mathsf{out}}} \left(
/// \mathsf{pt} \right)$$
///
/// ## Algorithm
/// ###### inputs:
/// - $\mathsf{ct}_{\mathsf{in}} = \left( \vec{a}_{\mathsf{in}} , b_{\mathsf{in}}\right) \in
///   \mathsf{LWE}^{n_{\mathsf{in}}}_{\vec{s}_{\mathsf{in}}}( \mathsf{pt} )$: an [`LWE
///   ciphertext`](`LweCiphertextEntity`) with $\vec{a}_{\mathsf{in}}=\left(a_0, \cdots
///   a_{n_{\mathsf{in}}-1}\right)$
/// - $\mathsf{KSK}_{\vec{s}_{\mathsf{in}}\rightarrow \vec{s}_{\mathsf{out}}}$: a [`key switching
///   key`](`LweKeyswitchKeyEntity`)
///
/// ###### outputs:
/// - $\mathsf{ct}_{\mathsf{out}} \in \mathsf{LWE}^{n_{\mathsf{out}}}_{\vec{s}_{\mathsf{out}}}
///   \left( \mathsf{pt} \right)$: an [`LWE ciphertext`](`LweCiphertextEntity`)
///
/// ###### algorithm:
/// 1. set $\mathsf{ct}=\left( 0 , \cdots , 0 ,  b_{\mathsf{in}} \right) \in
/// \mathbb{Z}_q^{(n_{\mathsf{out}}+1)}$ 2. compute $\mathsf{ct}_{\mathsf{out}} = \mathsf{ct} -
/// \sum_{i=0}^{n_{\mathsf{in}}-1} \mathsf{decompProduct}\left( a_i , \overline{\mathsf{ct}_i}
/// \right)$ 3. output $\mathsf{ct}_{\mathsf{out}}$
pub trait LweCiphertextDiscardingKeyswitchEngine<KeyswitchKey, InputCiphertext, OutputCiphertext>:
    AbstractEngine
where
    KeyswitchKey: LweKeyswitchKeyEntity,
    InputCiphertext: LweCiphertextEntity<KeyDistribution = KeyswitchKey::InputKeyDistribution>,
    OutputCiphertext: LweCiphertextEntity<KeyDistribution = KeyswitchKey::OutputKeyDistribution>,
{
    /// Keyswitch an LWE ciphertext.
    fn discard_keyswitch_lwe_ciphertext(
        &mut self,
        output: &mut OutputCiphertext,
        input: &InputCiphertext,
        ksk: &KeyswitchKey,
    ) -> Result<(), LweCiphertextDiscardingKeyswitchError<Self::EngineError>>;

    /// Unsafely keyswitch an LWE ciphertext.
    ///
    /// # Safety
    /// For the _general_ safety concerns regarding this operation, refer to the different variants
    /// of [`LweCiphertextDiscardingKeyswitchError`]. For safety concerns _specific_ to an engine,
    /// refer to the implementer safety section.
    unsafe fn discard_keyswitch_lwe_ciphertext_unchecked(
        &mut self,
        output: &mut OutputCiphertext,
        input: &InputCiphertext,
        ksk: &KeyswitchKey,
    );
}
