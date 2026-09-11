#include "P2pTransportKey.h"
#if defined(DISCRETE_PQ_P2P)
#include "P2pTransport.h"
#include <array>
#include <cstring>
#include <filesystem>
#include <memory>
#include <stdexcept>
#include <openssl/crypto.h>
#include <openssl/pem.h>
#include <openssl/rand.h>
#ifdef _WIN32
#include <windows.h>
#include <aclapi.h>
#include <sddl.h>
#else
#include <fcntl.h>
#include <sys/stat.h>
#include <unistd.h>
#endif

namespace CryptoNote {
namespace {
void check(bool ok, const char* message) { if (!ok) throw std::runtime_error(message); }
using Key = std::unique_ptr<EVP_PKEY, decltype(&EVP_PKEY_free)>;
using Bio = std::unique_ptr<BIO, decltype(&BIO_free)>;
struct Secret {
  std::array<char, 16384> bytes{};
  size_t size = 0;
  ~Secret() { OPENSSL_cleanse(bytes.data(), bytes.size()); }
};

std::string binding(const std::string& alpn, const std::string& name) {
  check(P2pTransportConfig::validName(name) && alpn.size() == 47 && alpn.compare(0, 15, "discrete-p2p/1/") == 0, "Invalid P2P key binding");
  return "Discrete-P2P-Key-v1 " + alpn + " " + name + "\n";
}

#ifdef _WIN32
struct Handle {
  HANDLE value = INVALID_HANDLE_VALUE;
  ~Handle() { if (value != INVALID_HANDLE_VALUE) CloseHandle(value); }
};
struct LocalMemory { void* value = nullptr; ~LocalMemory() { if (value) LocalFree(value); } };

void checkPermissions(HANDLE file) {
  PSECURITY_DESCRIPTOR sd = nullptr;
  PSID owner = nullptr;
  PACL acl = nullptr;
  check(GetSecurityInfo(file, SE_FILE_OBJECT, OWNER_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION, &owner, nullptr, &acl, nullptr, &sd) == ERROR_SUCCESS, "Cannot read P2P key permissions");
  LocalMemory descriptor{sd};
  check(acl != nullptr, "P2P key has an unrestricted DACL");
  alignas(DWORD) std::array<unsigned char, SECURITY_MAX_SID_SIZE> system{}, admins{};
  DWORD size = static_cast<DWORD>(system.size());
  check(CreateWellKnownSid(WinLocalSystemSid, nullptr, system.data(), &size) != 0, "Cannot identify SYSTEM");
  size = static_cast<DWORD>(admins.size());
  check(CreateWellKnownSid(WinBuiltinAdministratorsSid, nullptr, admins.data(), &size) != 0, "Cannot identify administrators");
  Handle token;
  check(OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &token.value) != 0, "Cannot identify key owner");
  alignas(TOKEN_USER) std::array<unsigned char, 1024> user{};
  DWORD used = 0;
  check(GetTokenInformation(token.value, TokenUser, user.data(), static_cast<DWORD>(user.size()), &used) != 0, "Cannot read current user");
  PSID current = reinterpret_cast<TOKEN_USER*>(user.data())->User.Sid;
  check(EqualSid(owner, current) != 0, "P2P key must belong to the current user");
  for (DWORD i = 0; i < acl->AceCount; ++i) {
    void* raw = nullptr;
    check(GetAce(acl, i, &raw) != 0, "Cannot inspect P2P key DACL");
    const auto* header = static_cast<ACE_HEADER*>(raw);
    if (header->AceFlags & INHERIT_ONLY_ACE) continue;
    if (header->AceType == ACCESS_DENIED_ACE_TYPE) continue;
    check(header->AceType == ACCESS_ALLOWED_ACE_TYPE, "Unsupported P2P key DACL entry");
    const auto* ace = static_cast<ACCESS_ALLOWED_ACE*>(raw);
    PSID sid = const_cast<DWORD*>(&ace->SidStart);
    check(EqualSid(sid, current) || EqualSid(sid, system.data()) || EqualSid(sid, admins.data()), "P2P key permissions grant another user access");
  }
}

void readSecret(const std::string& path, Secret& secret) {
  Handle file;
  file.value = CreateFileW(std::filesystem::u8path(path).c_str(), GENERIC_READ | READ_CONTROL, FILE_SHARE_READ, nullptr, OPEN_EXISTING, FILE_FLAG_OPEN_REPARSE_POINT, nullptr);
  check(file.value != INVALID_HANDLE_VALUE, "Cannot open P2P key file");
  BY_HANDLE_FILE_INFORMATION info{};
  check(GetFileInformationByHandle(file.value, &info) && !(info.dwFileAttributes & (FILE_ATTRIBUTE_DIRECTORY | FILE_ATTRIBUTE_REPARSE_POINT)) && info.nFileSizeHigh == 0 && info.nFileSizeLow < secret.bytes.size(), "P2P key must be a small regular file");
  checkPermissions(file.value);
  DWORD count = 0;
  check(ReadFile(file.value, secret.bytes.data(), static_cast<DWORD>(secret.bytes.size()), &count, nullptr) && count == info.nFileSizeLow, "Cannot read P2P key file");
  secret.size = count;
}

void writeSecret(const std::string& path, const void* data, size_t size) {
  Handle token;
  check(OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &token.value) != 0, "Cannot identify key owner");
  alignas(TOKEN_USER) std::array<unsigned char, 1024> user{};
  DWORD used = 0;
  check(GetTokenInformation(token.value, TokenUser, user.data(), static_cast<DWORD>(user.size()), &used) != 0, "Cannot read current user");
  LPWSTR sid = nullptr;
  check(ConvertSidToStringSidW(reinterpret_cast<TOKEN_USER*>(user.data())->User.Sid, &sid) != 0, "Cannot encode key owner");
  LocalMemory sidMemory{sid};
  const std::wstring sddl = std::wstring(L"O:") + sid + L"D:P(A;;FA;;;" + sid + L")(A;;FA;;;SY)(A;;FA;;;BA)";
  PSECURITY_DESCRIPTOR sd = nullptr;
  check(ConvertStringSecurityDescriptorToSecurityDescriptorW(sddl.c_str(), SDDL_REVISION_1, &sd, nullptr) != 0, "Cannot restrict P2P key permissions");
  LocalMemory descriptor{sd};
  SECURITY_ATTRIBUTES sa{sizeof(sa), sd, FALSE};
  Handle file;
  const auto wide = std::filesystem::u8path(path);
  file.value = CreateFileW(wide.c_str(), GENERIC_WRITE | READ_CONTROL, 0, &sa, CREATE_NEW, FILE_ATTRIBUTE_NORMAL, nullptr);
  check(file.value != INVALID_HANDLE_VALUE, "Cannot create P2P key file; existing keys are never overwritten");
  DWORD written = 0;
  check(WriteFile(file.value, data, static_cast<DWORD>(size), &written, nullptr) && written == size && FlushFileBuffers(file.value), "Cannot persist P2P key file");
}
#else
struct Fd { int value = -1; ~Fd() { if (value >= 0) ::close(value); } };
void readSecret(const std::string& path, Secret& secret) {
  // Reject non-regular files after open without first blocking on a FIFO.
  Fd file{::open(path.c_str(), O_RDONLY | O_CLOEXEC | O_NOFOLLOW | O_NONBLOCK)};
  check(file.value >= 0, "Cannot open P2P key file");
  struct stat info{};
  check(::fstat(file.value, &info) == 0 && S_ISREG(info.st_mode) && info.st_uid == ::geteuid() && !(info.st_mode & 0077) && info.st_size > 0 && static_cast<size_t>(info.st_size) < secret.bytes.size(), "P2P key must be an owner-only regular file");
  while (secret.size < static_cast<size_t>(info.st_size)) {
    const auto n = ::read(file.value, secret.bytes.data() + secret.size, static_cast<size_t>(info.st_size) - secret.size);
    check(n > 0, "Cannot read P2P key file");
    secret.size += static_cast<size_t>(n);
  }
}
void writeSecret(const std::string& path, const void* data, size_t size) {
  Fd file{::open(path.c_str(), O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC | O_NOFOLLOW, 0600)};
  check(file.value >= 0, "Cannot create P2P key file; existing keys are never overwritten");
  size_t done = 0;
  while (done < size) {
    const auto n = ::write(file.value, static_cast<const char*>(data) + done, size - done);
    check(n > 0, "Cannot persist P2P key file");
    done += static_cast<size_t>(n);
  }
  check(::fsync(file.value) == 0, "Cannot flush P2P key file");
}
#endif
}

EVP_PKEY* loadP2pTransportKey(const std::string& path, const std::string& alpn, const std::string& name) {
  Secret secret;
  readSecret(path, secret);
  const auto header = binding(alpn, name);
  check(secret.size > header.size() && std::memcmp(secret.bytes.data(), header.data(), header.size()) == 0, "P2P key belongs to a different network or service");
  Bio input(BIO_new_mem_buf(secret.bytes.data() + header.size(), static_cast<int>(secret.size - header.size())), BIO_free);
  check(input != nullptr, "Cannot parse P2P key file");
  Key key(PEM_read_bio_PrivateKey(input.get(), nullptr, [](char*, int, int, void*) { return 0; }, nullptr), EVP_PKEY_free);
  check(key && EVP_PKEY_is_a(key.get(), "ML-DSA-65") == 1, "P2P key must be ML-DSA-65");
  return key.release();
}

void createP2pTransportKey(const std::string& path, const std::string& alpn, const std::string& name) {
  const auto header = binding(alpn, name);
  Key key(EVP_PKEY_Q_keygen(nullptr, nullptr, "ML-DSA-65"), EVP_PKEY_free);
  check(key != nullptr, "ML-DSA-65 key generation failed");
  Bio output(BIO_new(BIO_s_mem()), BIO_free);
  check(output && BIO_write(output.get(), header.data(), static_cast<int>(header.size())) == static_cast<int>(header.size()) && PEM_write_bio_PrivateKey(output.get(), key.get(), nullptr, nullptr, 0, nullptr, nullptr) == 1, "Cannot encode P2P key");
  char* data = nullptr;
  const long size = BIO_get_mem_data(output.get(), &data);
  check(size > 0 && size < 16384, "P2P key file is too large");
  // Complete the protected temporary file before exposing the final path.
  std::array<unsigned char, 16> random{};
  check(RAND_bytes(random.data(), static_cast<int>(random.size())) == 1, "P2P key temporary name entropy failed");
  std::string temporary = path + ".new-";
  const char* hex = "0123456789abcdef";
  for (const auto byte : random) { temporary += hex[byte >> 4]; temporary += hex[byte & 15]; }
  try {
    writeSecret(temporary, data, static_cast<size_t>(size));
#ifdef _WIN32
    check(MoveFileExW(std::filesystem::u8path(temporary).c_str(), std::filesystem::u8path(path).c_str(), MOVEFILE_WRITE_THROUGH) != 0, "Cannot publish P2P key; destination must not exist");
#else
    check(::link(temporary.c_str(), path.c_str()) == 0, "Cannot publish P2P key; destination must not exist");
    ::unlink(temporary.c_str());
#endif
  } catch (...) {
    OPENSSL_cleanse(data, static_cast<size_t>(size));
    std::error_code ignored;
    std::filesystem::remove(std::filesystem::u8path(temporary), ignored);
    throw;
  }
  OPENSSL_cleanse(data, static_cast<size_t>(size));
}
}
#endif
