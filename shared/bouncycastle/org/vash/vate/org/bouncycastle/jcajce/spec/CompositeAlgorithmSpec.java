package org.vash.vate.org.bouncycastle.jcajce.spec;

import java.security.spec.AlgorithmParameterSpec;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

public class CompositeAlgorithmSpec
    implements AlgorithmParameterSpec
{
    public static class Builder
    {
        private List  algorithmNames = new ArrayList ();
        private List  parameterSpecs = new ArrayList ();

        public Builder()
        {
        }

        public Builder add(String algorithmName)
        {
            return add(algorithmName, null);
        }

        public Builder add(String algorithmName, AlgorithmParameterSpec parameterSpec)
        {
            if (!algorithmNames.contains(algorithmName))
            {
                algorithmNames.add(algorithmName);
                parameterSpecs.add(parameterSpec);

                return this;
            }
            throw new IllegalStateException("cannot build with the same algorithm name added");
        }

        public CompositeAlgorithmSpec build()
        {
            if (algorithmNames.isEmpty())
            {
                throw new IllegalStateException("cannot call build with no algorithm names added");
            }

            return new CompositeAlgorithmSpec(this);
        }
    }

    private final List  algorithmNames;
    private final List  parameterSpecs;

    public CompositeAlgorithmSpec(Builder builder)
    {
        this.algorithmNames = Collections.unmodifiableList(new ArrayList (builder.algorithmNames));
        this.parameterSpecs = Collections.unmodifiableList(new ArrayList (builder.parameterSpecs));
    }

    public List  getAlgorithmNames()
    {
        return algorithmNames;
    }

    public List  getParameterSpecs()
    {
        return parameterSpecs;
    }
}
