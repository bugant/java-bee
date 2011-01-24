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
import java.lang.reflect.Field;

public class Bee
{
    private static BeeLibrary lib = BeeLibrary.INSTANCE;
    private Pointer bee;
    private Mechanism symM;
    private Mechanism asymM;
    private Template sym;
    private Template pub;
    private Template priv;

    public Bee(String module, String pin) throws BeeException
    {
        lib.bee_reset_error();
        bee = lib.bee_new(module, pin);
        if (bee == null)
            throw new BeeException(lib.bee_get_last_error().intValue());
    }

    protected void finalize()
    {
        logout();
    }

    protected Pointer getPointer() {return bee;}

    public void logout()
    {
        if (bee == null)
            return;

        lib.bee_logout(this.bee);
        bee = null;
        sym = null;
        pub = null;
        priv = null;
        symM = null;
        asymM = null;
    }

    /**
     * Returns token information as a TokenInfo object
     *
     * @see TokenInfo
     *
     */
    public TokenInfo getTokenInfo() throws BeeException
    {
        Pointer info = lib.bee_get_token_info(bee);
        if (info == null)
            throw new BeeException(lib.bee_get_last_error().intValue());

        String[] tokenInfo = info.getStringArray(0);
        lib.bee_free_mem(info);
        return new TokenInfo(tokenInfo[TokenInfo.LABEL], tokenInfo[TokenInfo.MODEL],
                tokenInfo[TokenInfo.MANUFACTURER], tokenInfo[TokenInfo.SERIAL],
                tokenInfo[TokenInfo.HWD_VERSION], tokenInfo[TokenInfo.FIRM_VERSION]);
    }

    public Mechanism[] getSupportedMechanism() throws BeeException
    {
        NativeLong[] len = new NativeLong[1];
        Mechanism[] mechanisms;
        int i;

        Pointer ms = lib.bee_get_supported_mechanisms(bee, len);
        if (ms == null)
            throw new BeeException(lib.bee_get_last_error().intValue());

        mechanisms = new Mechanism[len[0].intValue()];
        for (i = 0; i < len[0].intValue(); i++)
            mechanisms[i] = new Mechanism(ms.getNativeLong(NativeLong.SIZE * i));

        return mechanisms;
    }


    public void setDefaultSymmetricMechanism(Mechanism m) throws BeeException
    {
        if (!m.isSymmetric())
            throw new BeeException("Invalid symmetric mechanism " + m);

        symM = m;
        lib.bee_set_default_sym_mechanism(bee, m.getMechanism());
    }

    public Mechanism getDefaultSymmetricMechanism() {return symM;}

    public void setDefaultAsymmetricMechanism(Mechanism m) throws BeeException
    {
        if (!m.isAsymmetric())
            throw new BeeException("Invalid asymmetric mechanism " + m);

        asymM = m;
        lib.bee_set_default_asym_mechanism(bee, m.getMechanism());
    }

    public Mechanism getDefaultAsymmetricMechanism() {return asymM;}

    public void setDefaultSymmetricTemplate(Template t)
    {
        sym = t;
        lib.bee_set_default_sym_template(bee, t.getPointer());
    }

    public Template getDefaultSymmetricTemplate() {return sym;}

    public void setDefaultPublicTemplate(Template t)
    {
        pub = t;
        lib.bee_set_default_pub_template(bee, t.getPointer());
    }

    public Template getDefaultPublicTemplate() {return pub;}

    public void setDefaultPrivateTemplate(Template t)
    {
        priv = t;
        lib.bee_set_default_priv_template(bee, t.getPointer());
    }

    public Template getDefaultPrivateTemplate() {return priv;}

    private ObjectHandle getKey(NativeLong h) throws BeeException
    {
        if (h.intValue() == -1)
            throw new BeeException(lib.bee_get_last_error().intValue());

        return new ObjectHandle(h, this);
    }

    public ObjectHandle generateKey() throws BeeException
    {
        lib.bee_reset_error();
        NativeLong key = lib.bee_generate_key(bee);
        return getKey(key);
    }

    public ObjectHandle generateKey(String name) throws BeeException
    {
        lib.bee_reset_error();
        NativeLong key = lib.bee_generate_named_key(bee, name);
        return getKey(key);
    }

    /* Generate a new key with the given template and label it with
     * name (if another label is declared in the template it is not taken into account) */
    public ObjectHandle generateKey(String name, Template t) throws BeeException
    {
        boolean label = true;
        String old = "";
        ObjectHandle key;

        try {old = t.getLabel();}
        catch (BeeException e) {label = false;}

        t.setLabel(name);
        key = generateKey(t);

        if (label)
            t.setLabel(old);
        else
            t.addLabel();

        return key;
    }

    public ObjectHandle generateKey(Template t) throws BeeException
    {
        lib.bee_reset_error();
        NativeLong key = lib.bee_generate_key_with_attrs(bee, t.getPointer());
        return getKey(key);
    }

    public ObjectHandle generateKey(Mechanism m) throws BeeException
    {
        lib.bee_reset_error();
        NativeLong key = lib.bee_generate_key_with_mechanism(bee, m.getMechanism());
        return getKey(key);
    }

    public ObjectHandle generateKey(Mechanism m, Template t) throws BeeException
    {
        lib.bee_reset_error();
        NativeLong key = lib.bee_generate_key_with_attrs_and_mechanism(bee, t.getPointer(), m.getMechanism());
        return getKey(key);
    }

    private ObjectHandle[] getKeys(Pointer p) throws BeeException
    {
        if (p == null)
            throw new BeeException(lib.bee_get_last_error().intValue());

        ObjectHandle[] keys = new ObjectHandle[2];
        // public key
        keys[0] = new ObjectHandle(p.getNativeLong(0), this);
        //private key
        keys[1] = new ObjectHandle(p.getNativeLong(NativeLong.SIZE), this);

        lib.bee_free_key_pair(p);
        return keys;
    }

    public ObjectHandle[] generateKeyPair(int len) throws BeeException
    {
        lib.bee_reset_error();
        Pointer pair = lib.bee_generate_key_pair(bee, new NativeLong(len));
        return getKeys(pair);
    }

    public ObjectHandle[] generateKeyPair(int len, String name) throws BeeException
    {
        lib.bee_reset_error();
        Pointer pair = lib.bee_generate_named_key_pair(bee, new NativeLong(len), name);
        return getKeys(pair);
    }

    public ObjectHandle[] generateKeyPair(Template pub, Template priv) throws BeeException
    {
        lib.bee_reset_error();
        Pointer pair = lib.bee_generate_key_pair_with_attrs(bee, pub.getPointer(), priv.getPointer());
        return getKeys(pair);
    }

    public ObjectHandle[] generateKeyPair(int len, Mechanism m) throws BeeException
    {
        lib.bee_reset_error();
        Pointer pair = lib.bee_generate_key_pair_with_mechanism(bee, new NativeLong(len), m.getMechanism());
        return getKeys(pair);
    }

    public ObjectHandle[] generateKeyPair(Mechanism m, Template pub, Template priv) throws BeeException
    {
        lib.bee_reset_error();
        Pointer pair = lib.bee_generate_key_pair_with_attrs_and_mechanism(bee, pub.getPointer(), priv.getPointer(), m.getMechanism());
        return getKeys(pair);
    }

    public ObjectHandle createObject(Template t) throws BeeException
    {
        lib.bee_reset_error();
        NativeLong o = lib.bee_create_object(bee, t.getPointer());
        return getKey(o);
    }

    public ObjectHandle copyObject(ObjectHandle o, Template t) throws BeeException
    {
        lib.bee_reset_error();
        NativeLong copy = lib.bee_copy_object(bee, new NativeLong(o.getHandle()), t.getPointer());
        return getKey(copy);
    }

    private ObjectHandle[] getSearchResult(Pointer found, NativeLong len)
    {
        ObjectHandle res[];
        int i, l;
        if (found == null)
            return new ObjectHandle[0]; 

        l = len.intValue();
        res = new ObjectHandle[l];
        for (i = 0; i < l; i++)
            res[i] = new ObjectHandle(found.getNativeLong(NativeLong.SIZE * i), this);

        lib.bee_free_mem(found);
        return res;
    }

    /**
     * Returns the handles of all objects stored in the token, whose label matches the given name.
     *
     */
    public ObjectHandle[] find(String name) throws BeeException
    {
        NativeLong len[] = new NativeLong[1];
        Pointer found;

        lib.bee_reset_error();
        found = lib.bee_find_objects_by_name(bee, name, len);
        Errors.checkError();

        return getSearchResult(found, len[0]);
    }

    /**
     * Returns the handles of all objects stored in the token, whose template matches the given one.
     *
     */
    public ObjectHandle[] find(Template t) throws BeeException
    {
        NativeLong len[] = new NativeLong[1];
        Pointer found;

        lib.bee_reset_error();
        found = lib.bee_find_objects(bee, t.getPointer(), len);
        Errors.checkError();

        return getSearchResult(found, len[0]);
    }

    private byte[] getBytes(Pointer p, NativeLong len) throws BeeException
    {
        byte[] res;

        if (p == null)
            throw new BeeException(lib.bee_get_last_error().intValue());

        res = p.getByteArray(0, len.intValue());
        lib.bee_free_mem(p);

        return res;
    }

    public byte[] symEncrypt(byte[] clear, ObjectHandle key) throws BeeException
    {
        lib.bee_reset_error();
        NativeLong len[] = new NativeLong[1];
        Pointer cipher = lib.bee_s_encrypt(bee, clear, new NativeLong(clear.length), new NativeLong(key.getHandle()), len);
        return getBytes(cipher, len[0]);
    }

    public byte[] asymEncrypt(byte[] clear, ObjectHandle key) throws BeeException
    {
        lib.bee_reset_error();
        NativeLong len[] = new NativeLong[1];
        Pointer cipher = lib.bee_a_encrypt(bee, clear, new NativeLong(clear.length), new NativeLong(key.getHandle()), len);
        return getBytes(cipher, len[0]);
    }

    public byte[] encrypt(byte[] clear, ObjectHandle key, Mechanism m) throws BeeException
    {
        lib.bee_reset_error();
        NativeLong len[] = new NativeLong[1];
        Pointer cipher = lib.bee_encrypt_with_mechanism(bee, clear, new NativeLong(clear.length), new NativeLong(key.getHandle()), m.getMechanism(), len);
        return getBytes(cipher, len[0]);
    }

    public byte[] symDecrypt(byte[] cipher, ObjectHandle key) throws BeeException
    {
        lib.bee_reset_error();
        NativeLong len[] = new NativeLong[1];
        Pointer clear = lib.bee_s_decrypt(bee, cipher, new NativeLong(cipher.length), new NativeLong(key.getHandle()), len);
        return getBytes(clear, len[0]);
    }

    public byte[] asymDecrypt(byte[] cipher, ObjectHandle key) throws BeeException
    {
        lib.bee_reset_error();
        NativeLong len[] = new NativeLong[1];
        Pointer clear = lib.bee_a_decrypt(bee, cipher, new NativeLong(cipher.length), new NativeLong(key.getHandle()), len);
        return getBytes(clear, len[0]);
    }

    public byte[] decrypt(byte[] cipher, ObjectHandle key, Mechanism m) throws BeeException
    {
        lib.bee_reset_error();
        NativeLong len[] = new NativeLong[1];
        Pointer clear = lib.bee_decrypt_with_mechanism(bee, cipher, new NativeLong(cipher.length), new NativeLong(key.getHandle()), m.getMechanism(), len);
        return getBytes(clear, len[0]);
    }

    public byte[] symWrap(ObjectHandle toBeWrappedKey, ObjectHandle wrappingKey) throws BeeException
    {
        lib.bee_reset_error();
        NativeLong len[] = new NativeLong[1];
        Pointer wrapped = lib.bee_s_wrap(bee, new NativeLong(wrappingKey.getHandle()), new NativeLong(toBeWrappedKey.getHandle()), len);
        return getBytes(wrapped, len[0]);
    }

    public byte[] asymWrap(ObjectHandle toBeWrappedKey, ObjectHandle wrappingKey) throws BeeException
    {
        lib.bee_reset_error();
        NativeLong len[] = new NativeLong[1];
        Pointer wrapped = lib.bee_a_wrap(bee, new NativeLong(wrappingKey.getHandle()), new NativeLong(toBeWrappedKey.getHandle()), len);
        return getBytes(wrapped, len[0]);
    }

    public byte[] wrap(ObjectHandle toBeWrappedKey, ObjectHandle wrappingKey, Mechanism m) throws BeeException
    {
        lib.bee_reset_error();
        NativeLong len[] = new NativeLong[1];
        Pointer wrapped = lib.bee_wrap_with_mechanism(bee, new NativeLong(wrappingKey.getHandle()),
                new NativeLong(toBeWrappedKey.getHandle()), m.getMechanism(), len);
        return getBytes(wrapped, len[0]);
    }

    private KeyType getUnwrapKeyType(String m) throws BeeException
    {
        String[] ms = m.split("_");
        int type;
        try {
            Field me = KeyType.class.getDeclaredField(ms[0]);
            type = ((Integer) me.get(null)).intValue();
        } catch (Exception e) {throw new BeeException("Cannot set the default template for an unwrapped symmetric key", e);}

        return new KeyType(type);
    }

    private KeyType getDefaultSymmetricKeyType() throws BeeException
    {
        return getUnwrapKeyType(getDefaultSymmetricMechanism().toString());
    }

    private KeyType getDefaultAsymmetricKeyType() throws BeeException
    {
        return getUnwrapKeyType(getDefaultAsymmetricMechanism().toString());
    }

    private Template getUnwrapTemplateSym() throws BeeException
    {
        Template t = new Template();
        t.setObjClass(new Pkcs11Class(Pkcs11Class.SECRET_KEY));
        t.setKeyType(getDefaultSymmetricKeyType());
        return t;
    }

    private Template getUnwrapTemplateAsym() throws BeeException
    {
        Template t = new Template();
        t.setObjClass(new Pkcs11Class(Pkcs11Class.PRIVATE_KEY));
        t.setKeyType(getDefaultAsymmetricKeyType());
        return t;
    }

    public ObjectHandle symUnwrapSym(byte[] wrappedKey, ObjectHandle wrappingKey) throws BeeException
    {
        return symUnwrap(wrappedKey, wrappingKey, getUnwrapTemplateSym());
    }

    public ObjectHandle symUnwrapAsym(byte[] wrappedKey, ObjectHandle wrappingKey) throws BeeException
    {
        return symUnwrap(wrappedKey, wrappingKey, getUnwrapTemplateAsym());
    }

    public ObjectHandle symUnwrap(byte[] wrappedKey, ObjectHandle wrappingKey, Template t) throws BeeException
    {
        lib.bee_reset_error();
        NativeLong key = lib.bee_s_unwrap_with_attrs(bee, new NativeLong(wrappingKey.getHandle()), wrappedKey,
                new NativeLong(wrappedKey.length), t.getPointer());
        return getKey(key);
    }

    public ObjectHandle asymUnwrapSym(byte[] wrappedKey, ObjectHandle wrappingKey) throws BeeException
    {
        return asymUnwrap(wrappedKey, wrappingKey, getUnwrapTemplateSym());
    }

    public ObjectHandle asymUnwrapAsym(byte[] wrappedKey, ObjectHandle wrappingKey) throws BeeException
    {
        return asymUnwrap(wrappedKey, wrappingKey, getUnwrapTemplateAsym());
    }

    public ObjectHandle asymUnwrap(byte[] wrappedKey, ObjectHandle wrappingKey, Template t) throws BeeException
    {
        lib.bee_reset_error();
        NativeLong key = lib.bee_a_unwrap_with_attrs(bee, new NativeLong(wrappingKey.getHandle()), wrappedKey,
                new NativeLong(wrappedKey.length), t.getPointer());
        return getKey(key);
    }

    // public ObjectHandle unwrap(byte[] wrappedKey, ObjectHandle wrappingKey, Mechanism m) throws BeeException
    // {
    //     NativeLong key = lib.bee_unwrap_with_mechanism(bee, new NativeLong(wrappingKey.getHandle()), m.getMechanism(),
    //             wrappedKey, new NativeLong(wrappedKey.length));
    //     return getKey(key);
    // }

    public ObjectHandle unwrap(byte[] wrappedKey, ObjectHandle wrappingKey, Mechanism m, Template t) throws BeeException
    {
        lib.bee_reset_error();
        NativeLong key = lib.bee_unwrap_with_attrs_and_mechanism(bee, new NativeLong(wrappingKey.getHandle()), m.getMechanism(),
                wrappedKey, new NativeLong(wrappedKey.length), t.getPointer());
        return getKey(key);
    }
}
