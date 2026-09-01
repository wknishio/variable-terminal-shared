
package org.vash.vate.org.bouncycastle.i18n.filter;

/**
 * Wrapper class to mark untrusted input.
 */
public class UntrustedInput 
{

    protected Object input;

    /**
     * Construct a new UntrustedInput instance.
     * @param input the untrusted input Object
     */
    public UntrustedInput(Object input) 
    {
        this.input = input;
    }

    /**
     * Returns the untrusted input as Object.
     * @return the  input</code> as Object
     */
    public Object getInput() 
    {
        return input;
    }

    /**
     * Returns the untrusted input convertet to a String.
     * @return the  input</code> as String
     */
    public String getString() 
    {
        return input.toString();
    }
    
    public String toString()
    {
        return input.toString();
    }

}
