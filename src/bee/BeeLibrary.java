/*
 *   Copyright (c) 2010 Matteo Centenaro
 *   
 *   Permission is hereby granted, free of charge, to any person obtaining a copy
 *   of this software and associated documentation files (the "Software"), to deal
 *   in the Software without restriction, including without limitation the rights
 *   to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 *   copies of the Software, and to permit persons to whom the Software is
 *   furnished to do so, subject to the following conditions:
 *   
 *   The above copyright notice and this permission notice shall be included in
 *   all copies or substantial portions of the Software.
 *   
 *   THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 *   IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 *   FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 *   AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 *   LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 *   OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
 *   THE SOFTWARE.
 */

package bee;
import com.sun.jna.*;

public interface BeeLibrary extends Library
{
    public BeeLibrary INSTANCE = (BeeLibrary) Native.loadLibrary("bee", BeeLibrary.class);

    void bee_free_mem(Pointer p);
    NativeLong bee_get_last_error();
    void bee_reset_error();

    Pointer bee_new_attrs();
    Pointer bee_copy_attrs(Pointer t);
    Pointer bee_malloc(NativeLong len);
    void bee_deep_free_attrs(Pointer t);
    void bee_free_attrs(Pointer t);

    void bee_add_token(Pointer t);
    boolean bee_get_token(Pointer t);
    void bee_set_token(Pointer t, boolean v);

    void bee_add_private(Pointer t);
    boolean bee_get_private(Pointer t);
    void bee_set_private(Pointer t, boolean v);

    void bee_add_modifiable(Pointer t);
    boolean bee_get_modifiable(Pointer t);
    void bee_set_modifiable(Pointer t, boolean v);

    void bee_add_label(Pointer t);
    Pointer bee_get_label(Pointer t);
    void bee_set_label(Pointer t, Pointer label, NativeLong len);

    void bee_add_class(Pointer t);
    NativeLong bee_get_class(Pointer t);
    void bee_set_class(Pointer t, Pointer cl);

    void bee_add_key_type(Pointer t);
    NativeLong bee_get_key_type(Pointer t);
    void bee_set_key_type(Pointer t, Pointer type);

    void bee_add_id(Pointer t);
    Pointer bee_get_id(Pointer t);
    void bee_set_id(Pointer t, Pointer id, NativeLong len);

    void bee_add_derive(Pointer t);
    boolean bee_get_derive(Pointer t);
    void bee_set_derive(Pointer t, boolean v);

    void bee_add_local(Pointer t);
    boolean bee_get_local(Pointer t);
    void bee_set_local(Pointer t, boolean v);

    void bee_add_encrypt(Pointer t);
    boolean bee_get_encrypt(Pointer t);
    void bee_set_encrypt(Pointer t, boolean v);

    void bee_add_decrypt(Pointer t);
    boolean bee_get_decrypt(Pointer t);
    void bee_set_decrypt(Pointer t, boolean v);

    void bee_add_wrap(Pointer t);
    boolean bee_get_wrap(Pointer t);
    void bee_set_wrap(Pointer t, boolean v);

    void bee_add_wrap_with_trusted(Pointer t);
    boolean bee_get_wrap_with_trusted(Pointer t);
    void bee_set_wrap_with_trusted(Pointer t, boolean v);

    void bee_add_unwrap(Pointer t);
    boolean bee_get_unwrap(Pointer t);
    void bee_set_unwrap(Pointer t, boolean v);

    void bee_add_sign(Pointer t);
    boolean bee_get_sign(Pointer t);
    void bee_set_sign(Pointer t, boolean v);

    void bee_add_sign_recover(Pointer t);
    boolean bee_get_sign_recover(Pointer t);
    void bee_set_sign_recover(Pointer t, boolean v);

    void bee_add_verify(Pointer t);
    boolean bee_get_verify(Pointer t);
    void bee_set_verify(Pointer t, boolean v);

    void bee_add_verify_recover(Pointer t);
    boolean bee_get_verify_recover(Pointer t);
    void bee_set_verify_recover(Pointer t, boolean v);

    void bee_add_never_extractable(Pointer t);
    boolean bee_get_never_extractable(Pointer t);
    void bee_set_never_extractable(Pointer t, boolean v);

    void bee_add_extractable(Pointer t);
    boolean bee_get_extractable(Pointer t);
    void bee_set_extractable(Pointer t, boolean v);

    void bee_add_always_sensitive(Pointer t);
    boolean bee_get_always_sensitive(Pointer t);
    void bee_set_always_sensitive(Pointer t, boolean v);

    void bee_add_sensitive(Pointer t);
    boolean bee_get_sensitive(Pointer t);
    void bee_set_sensitive(Pointer t, boolean v);

    void bee_add_trusted(Pointer t);
    boolean bee_get_trusted(Pointer t);
    void bee_set_trusted(Pointer t, boolean v);

    void bee_add_value(Pointer t);
    Pointer bee_get_value(Pointer t, NativeLong[] len);
    void bee_set_value(Pointer t, Pointer v, NativeLong len);

    void bee_add_value_len(Pointer t);
    NativeLong bee_get_value_len(Pointer t);
    void bee_set_value_len(Pointer t, Pointer len);

    void bee_add_modulus_bits(Pointer t);
    NativeLong bee_get_modulus_bits(Pointer t);
    void bee_set_modulus_bits(Pointer t, Pointer bits);

    void bee_add_modulus(Pointer t);
    Pointer bee_get_modulus(Pointer t, NativeLong[] len);
    void bee_set_modulus(Pointer t, Pointer v, NativeLong len);

    void bee_add_public_exponent(Pointer t);
    Pointer bee_get_public_exponent(Pointer t, NativeLong[] len);
    void bee_set_public_exponent(Pointer t, Pointer v, NativeLong len);

    void bee_add_private_exponent(Pointer t);
    Pointer bee_get_private_exponent(Pointer t, NativeLong[] len);
    void bee_set_private_exponent(Pointer t, Pointer v, NativeLong len);

    void bee_add_prime_1(Pointer t);
    Pointer bee_get_prime_1(Pointer t, NativeLong[] len);
    void bee_set_prime_1(Pointer t, Pointer v, NativeLong len);

    void bee_add_prime_2(Pointer t);
    Pointer bee_get_prime_2(Pointer t, NativeLong[] len);
    void bee_set_prime_2(Pointer t, Pointer v, NativeLong len);

    void bee_add_exponent_1(Pointer t);
    Pointer bee_get_exponent_1(Pointer t, NativeLong[] len);
    void bee_set_exponent_1(Pointer t, Pointer v, NativeLong len);

    void bee_add_exponent_2(Pointer t);
    Pointer bee_get_exponent_2(Pointer t, NativeLong[] len);
    void bee_set_exponent_2(Pointer t, Pointer v, NativeLong len);

    void bee_add_coefficient(Pointer t);
    Pointer bee_get_coefficient(Pointer t, NativeLong[] len);
    void bee_set_coefficient(Pointer t, Pointer v, NativeLong len);

    Pointer bee_new(String module, String pin);
    Pointer bee_new_and_configure(String module, String pin, NativeLong sym_mech, NativeLong asym_mech,
            Pointer sym_template, Pointer pub_template, Pointer priv_template);
    void bee_logout(Pointer bee);

    void bee_set_default_sym_mechanism(Pointer bee, NativeLong sym_mech);
    void bee_set_default_asym_mechanism(Pointer bee, NativeLong asym_mech);
    void bee_set_default_sym_template(Pointer bee, Pointer sym_template);
    void bee_set_default_pub_template(Pointer bee, Pointer pub_template);
    void bee_set_default_priv_template(Pointer bee, Pointer priv_template);

    Pointer bee_get_token_info(Pointer bee);
    Pointer bee_get_supported_mechanisms(Pointer bee, NativeLong[] len);

    void bee_get_attrs(Pointer bee, NativeLong o, Pointer t);
    void bee_set_attrs(Pointer bee, NativeLong o, Pointer t);

    NativeLong bee_generate_key(Pointer bee);
    NativeLong bee_generate_named_key(Pointer bee, String name);
    NativeLong bee_generate_key_with_attrs(Pointer bee, Pointer t);
    NativeLong bee_generate_key_with_mechanism(Pointer bee, NativeLong m);
    NativeLong bee_generate_key_with_attrs_and_mechanism(Pointer bee, Pointer t, NativeLong m);
    void bee_free_key_pair(Pointer keys);
    Pointer bee_generate_key_pair(Pointer bee, NativeLong len);
    Pointer bee_generate_named_key_pair(Pointer bee, NativeLong len, String name);
    Pointer bee_generate_key_pair_with_attrs(Pointer bee, Pointer pub, Pointer priv);
    Pointer bee_generate_key_pair_with_mechanism(Pointer bee, NativeLong len, NativeLong m);
    Pointer bee_generate_key_pair_with_attrs_and_mechanism(Pointer bee, Pointer pub, Pointer priv, NativeLong m);

    Pointer bee_find_objects_by_name(Pointer bee, String name, NativeLong[] len);
    Pointer bee_find_objects(Pointer bee, Pointer t, NativeLong[] len);
    NativeLong bee_create_object(Pointer bee, Pointer t);
    NativeLong bee_copy_object(Pointer bee, NativeLong o, Pointer t);
    void bee_destroy_object(Pointer bee, NativeLong o);

    Pointer bee_s_encrypt(Pointer bee, byte[] clear, NativeLong len, NativeLong key, NativeLong[] cipherLen);
    Pointer bee_a_encrypt(Pointer bee, byte[] clear, NativeLong len, NativeLong key, NativeLong[] cipherLen);
    Pointer bee_encrypt_with_mechanism(Pointer bee, byte[] clear, NativeLong len, NativeLong key, NativeLong m, NativeLong[] cipherLen);

    Pointer bee_s_decrypt(Pointer bee, byte[] cipher, NativeLong len, NativeLong key, NativeLong[] clearLen);
    Pointer bee_a_decrypt(Pointer bee, byte[] cipher, NativeLong len, NativeLong key, NativeLong[] clearLen);
    Pointer bee_decrypt_with_mechanism(Pointer bee, byte[] cipher, NativeLong len, NativeLong key, NativeLong m, NativeLong[] clearLen);

    Pointer bee_s_wrap(Pointer bee, NativeLong wrappingKey, NativeLong toBeWrappedKey, NativeLong[] len);
    Pointer bee_a_wrap(Pointer bee, NativeLong wrappingKey, NativeLong toBeWrappedKey, NativeLong[] len);
    Pointer bee_wrap_with_mechanism(Pointer bee, NativeLong wrappingKey, NativeLong toBeWrappedKey, NativeLong m, NativeLong[] len);

    // function removed from libbee -> there is no way to guess unwrapped key's class and type
    //NativeLong bee_s_unwrap(Pointer bee, NativeLong wrappingKey, byte[] wrapped, NativeLong len);
    NativeLong bee_s_unwrap_with_attrs(Pointer bee, NativeLong wrappingKey, byte[] wrapped, NativeLong len, Pointer t);
    // function removed from libbee -> there is no way to guess unwrapped key's class and type
    //NativeLong bee_a_unwrap(Pointer bee, NativeLong wrappingKey, byte[] wrapped, NativeLong len);
    NativeLong bee_a_unwrap_with_attrs(Pointer bee, NativeLong wrappingKey, byte[] wrapped, NativeLong len, Pointer t);
    // function removed from libbee -> there is no way to guess unwrapped key's class and type
    //NativeLong bee_unwrap_with_mechanism(Pointer bee, NativeLong wrappingKey, NativeLong m, byte[] wrapped, NativeLong len);
    NativeLong bee_unwrap_with_attrs_and_mechanism(Pointer bee, NativeLong wrappingKey, NativeLong m, byte[] wrapped, NativeLong len, Pointer t);
}
