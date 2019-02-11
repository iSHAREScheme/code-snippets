using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography.X509Certificates;

namespace iSHARE.Snippets
{
    public class CertificateValidator
    {
        public bool IsValid(X509Certificate2 certificate, IEnumerable<X509Certificate2> chain, DateTime moment)
        {
            var keyUsage = (X509KeyUsageExtension)certificate.Extensions
                .OfType<X509Extension>()
                .FirstOrDefault(c => c.Oid.FriendlyName == "Key Usage");

            if (keyUsage == null)
            {
                // "Key usage of the certificate was not found.";
                return false;
            }

            // The actual verifications of the certificate and the certificate chain
            var checks = new List<string>();
            AddCheck(checks, certificate.NotBefore <= moment && moment <= certificate.NotAfter, "Date validation status");
            AddCheck(checks, IsCertificatePartOfChain(certificate, chain), "Part of chain validation");
            AddCheck(checks, certificate.SignatureAlgorithm.FriendlyName == "sha256RSA", "SHA 256 signed");
            AddCheck(checks, certificate.PublicKey.Key.KeySize >= 2048, "Has 2048 private key");
            AddCheck(checks, !string.IsNullOrEmpty(certificate.SerialNumber), "Has serial number");

            var keyUsagesIsForDigitalOnly = keyUsage.KeyUsages.HasFlag(X509KeyUsageFlags.DigitalSignature) &&
                                                !(keyUsage.KeyUsages.HasFlag(X509KeyUsageFlags.KeyCertSign) ||
                                                  keyUsage.KeyUsages.HasFlag(X509KeyUsageFlags.CrlSign));

            AddCheck(checks, keyUsagesIsForDigitalOnly, "Key usage is for digital signature and not for CA");

            // If the checks list has any message, then it means a validation step did not pass.
            var result = checks.Any() ? false : true;

            return result;
        }

        private static void AddCheck(ICollection<string> checks, bool valid, string label)
        {
            if (!valid)
            {
                checks.Add(label);
            }
        }

        private bool IsCertificatePartOfChain(X509Certificate2 clientCertificate, IEnumerable<X509Certificate2> certificatesChain)
        {
            using (var chain = new X509Chain())
            {
                // Add the iSHARE CA to the in memory store, so the certificate can be validated against it. 
                // If the subject certificate is not signed be these two certificates, then the validation fails.
                chain.ChainPolicy.ExtraStore.Add(_rootCertificatePublicKey);
                chain.ChainPolicy.ExtraStore.Add(_intermediateCertificateAuthorityPublicKey);

                if (certificatesChain != null)
                {
                    // Add any other signing certificates that will complete the store.
                    chain.ChainPolicy.ExtraStore.AddRange(certificatesChain.ToArray());
                }

                // No CRL revocation check since the iSHARE PKI does not provide one yet.
                chain.ChainPolicy.RevocationMode = X509RevocationMode.NoCheck;
                var isValidByPolicy = chain.Build(clientCertificate);

                if (!isValidByPolicy)
                {
                    var statuses = chain.ChainElements.OfType<X509ChainElement>().SelectMany(c => c.ChainElementStatus);

                    if (statuses.All(c => c.Status.HasFlag(X509ChainStatusFlags.UntrustedRoot)))
                    {
                        // allow untrusted root
                        // for the places where the iSHARE root is not installed (build server)
                        isValidByPolicy = true;
                    }
                }

                return isValidByPolicy;
            }
        }

        private static readonly X509Certificate2 _rootCertificatePublicKey = new X509Certificate2(Convert.FromBase64String(
            @"MIIFbTCCA1WgAwIBAgIIHjjfTuSjFjMwDQYJKoZIhvcNAQELBQAwRDEVMBMGA1UE
AwwMaVNIQVJFVGVzdENBMQ0wCwYDVQQLDARUZXN0MQ8wDQYDVQQKDAZpU0hBUkUx
CzAJBgNVBAYTAk5MMB4XDTE4MDcyMzE1MDUxM1oXDTI4MDcyMDE1MDUxM1owRDEV
MBMGA1UEAwwMaVNIQVJFVGVzdENBMQ0wCwYDVQQLDARUZXN0MQ8wDQYDVQQKDAZp
U0hBUkUxCzAJBgNVBAYTAk5MMIICIjANBgkqhkiG9w0BAQEFAAOCAg8AMIICCgKC
AgEA4HIQ2eGXSP0bqgOs6IbrxTw/0u6XyRi5H/Z+j8hPzFeS/n7UcDs+48GYSgEN
1cIDBAGWjnwNM6u4RpQiG8xl7YtjWymwKm4HXtLAQqt72arY37PSF30Xi6VPBant
PTdaa+9zCU8CyFnEZ2fKTk1Sug36g6F6OjdgCCGkjdppKVyNIl5OW+kjFq2A9Gvt
BRGEwR2etotKtsIHI/g4cXOFZjtCCtPoEmjQ66fSwa7AjolpBb2PcssCVpb5c6sA
fp20JNn84kDQEoHjeoyNAqctBEIsRZF4kpTn4YhSXq0TH/kRtEEfNEmzLEOSaDWP
yL8qJJpx1aPAye0fkGfJi51cGRrFxf7jfN99Tjdf3yxwtT/yQquWLp6VLdqjJLk9
btGk+BiS9iVtw41Ec2ysX/3g0xeVVFGtyCwACWpyIx+Qm80KjVXkYDxhGiLQjQIz
VolPEVUDAZnw+LCmg3OY9Iy0PXTV0x3CKHM+C3ukZWkS1d3CSgDVl1+cpHJT4m6f
KnncO77yVO0yrW5218UGaYALOh8PHow36e9cB2c0bT2d1CHRekSl4+Bx+xQMGwsP
yveGgpkHidZtYRDP4E/HxNKy+wfByQeSu4YcUc8EHxy9qzxae28QfZn7s47V/PjA
k0dLZyQDonE9Q10OkMV15Dp9PWGeCQJri5JdOnr+iD8DdHsCAwEAAaNjMGEwDwYD
VR0TAQH/BAUwAwEB/zAfBgNVHSMEGDAWgBStrcqxOdRWdjwpeCXRGKJAG2goTDAd
BgNVHQ4EFgQUra3KsTnUVnY8KXgl0RiiQBtoKEwwDgYDVR0PAQH/BAQDAgGGMA0G
CSqGSIb3DQEBCwUAA4ICAQBCGYNl/1HFWVhDoPmkpVqm30ryqf6dWx1rxTW1lk9a
VUOlR9IRHPp1z/F/4fb6mIXFjFYw5lU2faHV9op4rNuGqRRSLiQPVvOXxDlxqA6D
mqziREvttG0uLZ/FOycKY53pWFCzG2keq6OId9JSpFmQDOiF7WSuifPLuwADkUw+
oZYGgWmbwQO0lXtw7XOny37nLZkYl89bRhIg/7fb+Xnb8914SMv0kGlk1kCeyL6F
XdXRTaat5c9XlJr9yzOUIDn54bY1BKT6YtiyJfvCNav/Fb24v5eq2Z9mBdZ70Cc9
5gPjqqxMZUgJo57YvhLfXDwxbWZWYC+WcR8nHkY+tZBlIih2CXHsOar5oH6drMdt
MIZz3UZJ/CxFG1u23Uz1jBfm/EggdKhOVnT6edruVoteWWCDB9Hdhxz8RAVYn5dq
UjkjRq4W9QAfJusrPZGBndT7yNaY/FHYKIq+uTarWibjdxtdYClaTwOxk5IqKNF9
eCKbPmxs1mlZrSLjMQFY3U9RkvzI+3IlAFkctUeabpkmXxnuWWSV2FJO9ZrONMWu
tw+567PK5gzM0FqQvb7sCxZuQDl5Ct6ZWlts2Y72t6pPjRI17+S8++a2vQdxBcNQ
0xF2tjvzTviZ3C5EqIeazWdgIZkqfWZkS8v+0MAvNZY+bbx+vSwLOoHQWrf/OCL7
AQ=="));

        private static readonly X509Certificate2 _intermediateCertificateAuthorityPublicKey = new X509Certificate2(Convert.FromBase64String(
            @"MIIFcTCCA1mgAwIBAgIISFRJwGAAyjUwDQYJKoZIhvcNAQELBQAwRDEVMBMGA1UE
AwwMaVNIQVJFVGVzdENBMQ0wCwYDVQQLDARUZXN0MQ8wDQYDVQQKDAZpU0hBUkUx
CzAJBgNVBAYTAk5MMB4XDTE4MDcyMzE1MTQxM1oXDTIzMDcyMjE1MTQxM1owSDEZ
MBcGA1UEAwwQaVNIQVJFVGVzdENBX1RMUzENMAsGA1UECwwEVGVzdDEPMA0GA1UE
CgwGaVNIQVJFMQswCQYDVQQGEwJOTDCCAiIwDQYJKoZIhvcNAQEBBQADggIPADCC
AgoCggIBAPueRXUGSUgu7qpAWJjAVH9z319XnuFleVeO/XxbJ6U4ixXRKvW8vKTV
1dRcfQeCqXk7ua/ZsqNrq89Ex95b0nqGUv1NoK2T8yEAkQzyzYZpW4c2YMCcg5am
RwCfYahHtJmXJWqREevM5kJoOacKH/GUbsemT94B0KXSNQ6IWcJyjpuaoDpb6Wd9
7T2luP1IQ5gkfwU38CZJKVkbY3eJkLlOwwtFsFPP2M4f8u479OkMUr5/m+xn73Ja
ZSJFOHvIN6DFpAls2ax7BhUSlbKM3YEuNb0O4oO5ynDFHvmllp6Nu0F2Xo0Bu0P/
uqb/08XvVWne7wcwWZR9+d78q+OlfC/m+wAwAqmQHEr8hJNvR6S/84HAjUdMyGcY
Tvov0tb0Zw/AKwDg8PC9UFRYb0cBr0+/GfgmJP5QMAfLqkXmZwYQSZ1FamNlJlmx
0sYZQSaudG0+Xkc991+Zw/x8uWZi9qQZeBOdwnI2xf/HJXHJsaZfDvTp5i8iVP75
1rhinwLi2dZnmSsQ96gvtTQBo4J5AvF+s9Il+TukeLtlKABaoMwz8wYBCnfKvUtk
p7JU5ijjYFaqQsFR3RpOHXcH/spZTYHuSs1OpHVbr0/cFtWZpv4tSQklPqCjddSA
SH9k3OBAhxenyXLkn9U9AAI34pZbFV+mksGGrN7ukk4obStI7z/5AgMBAAGjYzBh
MA8GA1UdEwEB/wQFMAMBAf8wHwYDVR0jBBgwFoAUra3KsTnUVnY8KXgl0RiiQBto
KEwwHQYDVR0OBBYEFBY85yDp1pTvH+Wi8bj8vurfLDeBMA4GA1UdDwEB/wQEAwIB
hjANBgkqhkiG9w0BAQsFAAOCAgEAeIJw1nnoOrsamueW4cZPLzrnuHSEvv1SEL1b
fB6F73anmxbq9+OYW6qojhxvorHTFzoQynsPmbso7t4b3HAtWaOlp3DKZUTpzOlL
nQ9gsDDfDVSJsJ5jxglDFZm0A07Ld3CxZhnzWf9A0QgNqN5hCcOsrl4uDMvZz+M9
kL/iksCx4X0so2OSm1QakraAR3umPc2ooAacPsAVCllekXFJ9DFjJ5Uv+rg8ZKHH
LGrP19o/AsXJYpKP/ttk5tBuA4JB20aShbcC539rA+Qc+kDHyRnL0aJyRYeBgY1i
AtuzXzMOk53XV+aJogDp3gF73s1c1YyIRHt7ofQG/0Zlwc/41CxOD+lyzG34RkgI
UO6UfjiGCFPmZQ2HkpKyqLifraRdqrHXOhoVd7HidYIihnZKDkLi1cfeo2mz8tWi
UzA+dPchaIElpQJPTjSbLjF2I19QyB8fuPazPfNIjHrXaKlaS3luKcFiqOYgcwWf
dZmDzxIU6PY2bzx/SDMoU24rAVSuGAYBIAlwf2pxmtLcbMA6bYr4trmQfbJrM8f8
JZgGQoItrpzrKjBJ2gFRt+065NMTNkB5rw8Xr56j5djkqB0/qHIcF2TiY/k/81Rm
TCYxrVHzM1czhXHXYzvnd2Jl1wJXyacWl7FiPaggw0YQidWHGMdItEuD/8SXiCXl
1OIvvic="));
    }
}
