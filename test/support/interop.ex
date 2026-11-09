defmodule Tspex.Interop do
  @moduledoc false
  # The other implementations of the interop tests, found on this system:
  #
  #   TSPEX_OPENSSL    an OpenSSL binary, 3.0 or later
  #   TSPEX_LIBRESSL   a LibreSSL binary (the openssl of macOS)
  #   TSPEX_JARSIGNER  the jarsigner of a JDK, 17 or later (keytool and jar
  #                    are looked for in the same folder)
  #
  # Without the variable, a few usual places are tried. A tool that is not
  # found is skipped, unless TSPEX_REQUIRE_INTEROP names it, as in
  # "openssl,jarsigner", or is "all": then its tests fail.

  @tools [:openssl, :libressl, :jarsigner]

  def tools, do: @tools

  @doc "`{path, version text}` of a tool, or `nil`."
  def find(:openssl),
    do:
      openssl(
        "TSPEX_OPENSSL",
        ["/opt/homebrew/opt/openssl@3/bin/openssl", "openssl"],
        ~r/^OpenSSL [3-9]\./
      )

  def find(:libressl),
    do: openssl("TSPEX_LIBRESSL", ["/usr/bin/openssl", "openssl"], ~r/^LibreSSL /)

  def find(:jarsigner) do
    java_home = System.get_env("JAVA_HOME")
    candidates = ["/opt/homebrew/opt/openjdk/bin/jarsigner", "jarsigner"]

    candidates =
      if java_home,
        do: [Path.join([java_home, "bin", "jarsigner"]) | candidates],
        else: candidates

    first_found("TSPEX_JARSIGNER", candidates, fn path ->
      case System.cmd(path, ["-version"], stderr_to_stdout: true) do
        {"jarsigner " <> _ = version, 0} -> String.trim(version)
        _ -> nil
      end
    end)
  end

  def required?(tool) do
    names = System.get_env("TSPEX_REQUIRE_INTEROP", "") |> String.split(",", trim: true)
    "all" in names or Atom.to_string(tool) in names
  end

  @doc "Runs a tool, with its output and exit status."
  def run(path, args, opts \\ []) do
    System.cmd(path, args, [stderr_to_stdout: true] ++ opts)
  end

  @doc "The program `name` of the JDK that `jarsigner` belongs to."
  def jdk_tool(jarsigner, name), do: Path.join(Path.dirname(jarsigner), name)

  @doc "A certificate in DER as PEM."
  def pem(der), do: :public_key.pem_encode([{:Certificate, der, :not_encrypted}])

  @doc """
  A throwaway CA and a TSA of the tool in `dir`, for the tool to answer
  requests with `reply/4`. `kind` is `:rsa` or `:ec`. Returns the root and
  the certificate of the TSA in DER.
  """
  def make_tsa({path, version}, dir, kind) do
    ca_config = """
    [req]
    distinguished_name = dn
    prompt = no
    x509_extensions = ca_ext
    [dn]
    C = BR
    O = tspex interop
    CN = tspex interop CA
    [ca_ext]
    basicConstraints = critical,CA:true
    keyUsage = critical,keyCertSign,cRLSign
    subjectKeyIdentifier = hash
    """

    tsa_ext = """
    basicConstraints = critical,CA:false
    keyUsage = critical,digitalSignature
    extendedKeyUsage = critical,timeStamping
    subjectKeyIdentifier = hash
    authorityKeyIdentifier = keyid
    """

    # The ESSCertIDv2 of the tool's own tokens is an OpenSSL option.
    ess = if version =~ ~r/^OpenSSL/, do: "ess_cert_id_alg = sha256\n", else: ""

    ts_config = """
    [ tsa ]
    default_tsa = t
    [ t ]
    serial = #{dir}/serial
    crypto_device = builtin
    signer_cert = #{dir}/tsa.pem
    certs = #{dir}/tsa.pem
    signer_key = #{dir}/tsa.key
    signer_digest = sha256
    default_policy = 1.2.3.4.1
    other_policies = 1.2.3.4.5.6, 1.2.3.4.5.7
    digests = sha1, sha224, sha256, sha384, sha512
    accuracy = secs:1
    ordering = yes
    tsa_name = yes
    #{ess}
    """

    File.write!(Path.join(dir, "ca.cnf"), ca_config)
    File.write!(Path.join(dir, "tsa.ext"), tsa_ext)
    File.write!(Path.join(dir, "ts.cnf"), ts_config)
    File.write!(Path.join(dir, "serial"), "01\n")

    in_dir = fn args -> ok!(run(path, args, cd: dir), args) end

    in_dir.(~w(genrsa -out ca.key 2048))

    in_dir.(~w(req -x509 -new -key ca.key -sha256 -days 30 -config ca.cnf -out ca.pem))

    case kind do
      :rsa -> in_dir.(~w(genrsa -out tsa.key 2048))
      :ec -> in_dir.(~w(ecparam -name prime256v1 -genkey -noout -out tsa.key))
    end

    in_dir.(
      ["req", "-new", "-key", "tsa.key", "-subj", "/C=BR/O=tspex interop/CN=interop TSA #{kind}"] ++
        ~w(-config ca.cnf -out tsa.csr)
    )

    in_dir.(
      ~w(x509 -req -in tsa.csr -CA ca.pem -CAkey ca.key -CAcreateserial -sha256 -extfile tsa.ext -days 30 -out tsa.pem)
    )

    %{root: der(dir, "ca.pem"), cert: der(dir, "tsa.pem")}
  end

  @doc "The answer of the tool (a `TimeStampResp` in DER) to a request in DER."
  def reply({path, _version}, dir, request_der, token? \\ false) do
    File.write!(Path.join(dir, "q.tsq"), request_der)
    out = if token?, do: ~w(-token_out), else: []

    args =
      ~w(ts -reply -config ts.cnf -queryfile q.tsq -out r.tsr) ++ out

    ok!(run(path, args, cd: dir), args)
    File.read!(Path.join(dir, "r.tsr"))
  end

  defp der(dir, pem_file) do
    [{:Certificate, der, _}] = :public_key.pem_decode(File.read!(Path.join(dir, pem_file)))
    der
  end

  defp ok!({_output, 0} = result, _args), do: result

  defp ok!({output, status}, args),
    do: raise("#{hd(args)} exited with #{status}: #{String.slice(output, 0, 400)}")

  defp openssl(variable, candidates, pattern) do
    first_found(variable, candidates, fn path ->
      with {version, 0} <- System.cmd(path, ["version"], stderr_to_stdout: true),
           true <- version =~ pattern do
        String.trim(version)
      else
        _ -> nil
      end
    end)
  end

  # With the variable set, only its value is tried.
  defp first_found(variable, candidates, probe) do
    candidates =
      case System.get_env(variable) do
        nil -> candidates
        path -> [path]
      end

    Enum.find_value(candidates, fn candidate ->
      with path when is_binary(path) <- System.find_executable(candidate),
           version when is_binary(version) <- probe.(path) do
        {path, version}
      end
    end)
  end
end
