# Validate an incoming API token with Daywalker Auth, with an RFC 9421 signed request. Stdlib only.
# Env: DAYWALKER_API_KEY, DAYWALKER_SIGNING_KEY (base64 PKCS#8 Ed25519), DAYWALKER_KEY_ID,
#      optional DAYWALKER_URL (default https://auth.daywalker.dev).
require "base64"
require "digest"
require "json"
require "net/http"
require "openssl"
require "securerandom"
require "uri"

BASE = URI(ENV.fetch("DAYWALKER_URL", "https://auth.daywalker.dev"))
PATH = "/api/v1/tokens/validate"

def validate_token(token)
  body = JSON.generate(token: token)
  digest = "sha-256=:#{Base64.strict_encode64(Digest::SHA256.digest(body))}:"
  params = %{("@method" "@path" "@authority" "content-digest");created=#{Time.now.to_i};keyid="#{ENV.fetch('DAYWALKER_KEY_ID')}";alg="ed25519";nonce="#{SecureRandom.hex(12)}"}
  base = [
    '"@method": POST', %("@path": #{PATH}), %("@authority": #{BASE.host}),
    %("content-digest": #{digest}), %("@signature-params": #{params})
  ].join("\n")
  key = OpenSSL::PKey.read(Base64.decode64(ENV.fetch("DAYWALKER_SIGNING_KEY")))
  signature = Base64.strict_encode64(key.sign(nil, base))

  req = Net::HTTP::Post.new(PATH, "Content-Type" => "application/json",
                            "Authorization" => "Bearer #{ENV.fetch('DAYWALKER_API_KEY')}",
                            "Content-Digest" => digest, "Signature-Input" => "sig1=#{params}",
                            "Signature" => "sig1=:#{signature}:")
  req.body = body
  res = Net::HTTP.start(BASE.host, BASE.port, use_ssl: BASE.scheme == "https") { |http| http.request(req) }
  JSON.parse(res.body) # 4xx/5xx still carry a JSON error body
end

if $PROGRAM_NAME == __FILE__
  result = validate_token(ARGV.fetch(0))
  if result["valid"]
    puts "Authorized user: #{result['userId']} quota: #{result['rateLimit']['remaining']}"
  else
    puts "Rejected [#{result['error']}]: #{result['message']}"
  end
end
