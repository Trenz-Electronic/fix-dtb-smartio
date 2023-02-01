// vim: tabstop=2:shiftwidth=2:expandtab:
/* \file FixDtbSmartio.cpp
   \brief FixDtbSmartio reorders device tree nodes in image.ub file such that the bigges buffers come first.
 */
#if defined(_MSC_VER)
#include <windows.h>
#include <bcrypt.h>
#else
#include <crypto++/sha.h>
#endif

#include <algorithm>  // std::sort
#include <memory>     // std::make_unique
#include <stdexcept>  // std::runtime_error
#include <string>
#include <vector>

#include <ctype.h>  // toupper.
#include <libfdt.h> // fdt_32
#include <sys/stat.h> // struct stat.
#include <stdint.h> // uint32_t, etc
#include <stdio.h>  // fopen
#include <string.h> // strlen


static void print_usage()
{
  printf("Usage: FixDtbSmartio FILE1 [FILE2 ... FILEN]\n");
}

#if defined(_MSC_VER)
# define NT_SUCCESS(Status)          (((NTSTATUS)(Status)) >= 0)
# define STATUS_UNSUCCESSFUL         ((NTSTATUS)0xC0000001L)  // Must be Windows.

/// <summary>
/// Hash function from the Windows Cryptography API: Next Generation.
/// 
/// This is patterned after the libcrypto++'s HashTransformation.
/// </summary>
class HashAlgorithm {
private:
  BCRYPT_ALG_HANDLE       hAlg;
  BCRYPT_HASH_HANDLE      hHash;
  DWORD                   cbData;
  DWORD                   cbHash;
  DWORD                   cbHashObject;
  std::vector<uint8_t>    hash_object;
  std::wstring            hash_algorithm;

  void cleanup() {
    if (hAlg) {
      BCryptCloseAlgorithmProvider(hAlg, 0);
    }
    hAlg = nullptr;

    if (hHash) {
      BCryptDestroyHash(hHash);
    }
    hHash = nullptr;
  }
public:
  /// <summary>
  /// Create new hasher. Recognized values: sha1, sha256.
  /// </summary>
  HashAlgorithm(const char* algo) : hAlg(nullptr), hHash(nullptr), cbData(0), cbHash(0), cbHashObject(0)
  {
    NTSTATUS                status = STATUS_UNSUCCESSFUL;

    try {
      for (int i = 0; algo[i] != 0; ++i) {
        hash_algorithm += (wchar_t)toupper(algo[i]);
      }

      //open an algorithm handle
      if (!NT_SUCCESS(status = BCryptOpenAlgorithmProvider(&hAlg, hash_algorithm.c_str(), nullptr, 0))) {
        throw std::runtime_error("BCryptOpenAlgorithmProvider");
      }

      //calculate the size of the buffer to hold the hash object
      if (!NT_SUCCESS(status = BCryptGetProperty(hAlg, BCRYPT_OBJECT_LENGTH, (PBYTE)&cbHashObject, sizeof(DWORD), &cbData, 0))) {
        throw std::runtime_error("BCryptOpenAlgorithmProvider BCRYPT_OBJECT_LENGTH");
      }

      //calculate the length of the hash
      if (!NT_SUCCESS(status = BCryptGetProperty(hAlg, BCRYPT_HASH_LENGTH, (PBYTE)&cbHash, sizeof(DWORD), &cbData, 0))) {
        throw std::runtime_error("BCryptGetProperty BCRYPT_HASH_LENGTH");
      }

      hash_object.resize(cbHashObject);
      //create a hash
      if (!NT_SUCCESS(status = BCryptCreateHash(hAlg, &hHash, &hash_object[0], cbHashObject, NULL, 0, 0))) {
        throw std::runtime_error("BCryptCreateHash");
      }
    }
    catch (...) {
      cleanup();
      throw;
    }
  }

  unsigned int DigestSize() const
  {
    return cbHash;
  }

  void Update(const uint8_t* src, const size_t size) {
    NTSTATUS                status = STATUS_UNSUCCESSFUL;
    if (!NT_SUCCESS(status = BCryptHashData(hHash, (PBYTE)src, size, 0))) {
      throw std::runtime_error("BCryptHashData");
    }
  }

  void Final(uint8_t* dst) {
    NTSTATUS                status = STATUS_UNSUCCESSFUL;
    if (!NT_SUCCESS(status = BCryptFinishHash(hHash, &dst[0], cbHash, 0))) {
      throw std::runtime_error("BCryptFinishHash");
    }
  }

  ~HashAlgorithm() {
    cleanup();
  }
};
#endif

static void hash_data(std::vector<uint8_t>& dst, const uint8_t* src, const size_t size, const char* algo)
{
#if defined(_MSC_VER)
  auto hasher = std::make_unique<HashAlgorithm>(algo);
#else
  std::unique_ptr<CryptoPP::HashTransformation> hasher;
  if (strcasecmp(algo, "sha1") == 0) {
    hasher = std::make_unique<CryptoPP::SHA1>();
  }
  else if (strcasecmp(algo, "sha256") == 0) {
    hasher = std::make_unique<CryptoPP::SHA256>();
  }
  else {
    throw std::runtime_error("Unknown hash algorithm specified.");
  }

#endif
  dst.resize(hasher->DigestSize());
  hasher->Update(src, size);
  hasher->Final(&dst[0]);
}

static std::vector<uint8_t> read_all_bytes(const char* filepath)
{
  struct stat fileinfo;
  const int r_stat = stat(filepath, &fileinfo);
  if (r_stat != 0) {
    throw std::runtime_error("File not found");
  }
  if (fileinfo.st_size == 0) {
    throw std::runtime_error("Empty file");
  }

  FILE* f = fopen(filepath, "rb");
  if (f == nullptr) {
    throw std::runtime_error("Cannot open");
  }
  std::vector<uint8_t>  r(fileinfo.st_size);

  int this_round = 0;
  for (unsigned int so_far = 0; so_far < r.size(); so_far += this_round) {
    this_round = fread(&r[so_far], 1, r.size() - so_far, f);
    if (this_round == 0) {
      throw std::runtime_error("Unexpected EOF");
    }
    if (this_round < 0) {
      throw std::runtime_error("Read error");
    }
  }
  return r;
}

static void write_all_bytes(const char* filepath, const uint8_t* data_begin, const uint8_t* data_end)
{
  FILE* f = fopen(filepath, "wb");
  if (f == nullptr) {
    throw std::runtime_error("Cannot open");
  }

  int this_round = 0;
  for (const uint8_t* so_far = data_begin; so_far != data_end; so_far += this_round) {
    this_round = fwrite(so_far, 1, data_end - so_far, f);
    if (this_round <= 0) {
      throw std::runtime_error("Write error");
    }
  }
}

struct Property {
  const char* name;
  uint8_t* data;
  size_t data_size;
  unsigned int begin_index;
  unsigned int end_index;
};

struct Node {
  const char* name;
  unsigned int begin_index;
  unsigned int end_index;
  std::vector<Property> properties;
  std::vector<Node> nodes;

  unsigned int payload_begin_index() const
  {
    return begin_index + strlen(name)/sizeof(fdt32_t) + 2u;
  }

  unsigned int payload_end_index() const
  {
    return end_index - 1u;
  }

  Property* find_property(const char* propname)
  {
    for (size_t i = 0; i < properties.size(); ++i) {
      Property& prop = properties[i];
      if (strcmp(prop.name, propname) == 0) {
        return &prop;
      }
    }
    return nullptr;
  }

  const Property* find_property(const char* propname) const
  {
    for (size_t i = 0; i < properties.size(); ++i) {
      const Property& prop = properties[i];
      if (strcmp(prop.name, propname) == 0) {
        return &prop;
      }
    }
    return nullptr;
  }

  Node* find_node(const char* path) {
    const char* name_end = strchr(path, '/');
    size_t name_length;
    const char* next_path;
    if (name_end == nullptr) {
      name_length = strlen(path);
      if (name_length == 0) {
        return this; // must be a match.
      }
      next_path = path + name_length;
    }
    else {
      name_length = name_end - path;
      next_path = name_end + 1;
    }
    for (size_t i_node = 0; i_node < nodes.size(); ++i_node) {
      Node& child_node = nodes[i_node];
      if (strncmp(child_node.name, path, name_length) == 0) {
        return child_node.find_node(next_path);
      }
    }
    return nullptr;
  }

};

class DtbScanner {
public:
  /// <summary>
  /// Pointer to the strings area.
  /// </summary>
  const char*   strings;

  /// <summary>
  /// Pointer to the structs area.
  /// </summary>
  fdt32_t* structs;

  /// <summary>
  /// Size of the structs.
  /// </summary>
  unsigned int structs_size;

  /// <summary>
  /// Our root node.
  /// </summary>
  Node root;

  /// <summary>
  /// NOP count.
  /// </summary>
  unsigned int nop_count;

  DtbScanner(uint8_t* fdt_blob, const size_t size)
  {
    const unsigned int strings_offset = fdt_off_dt_strings(fdt_blob);
    strings = reinterpret_cast<const char*>(&fdt_blob[strings_offset]);

    const unsigned int struct_offset = fdt_off_dt_struct(fdt_blob);
    structs = reinterpret_cast<fdt32_t*>(&fdt_blob[struct_offset]);
    structs_size = (strings_offset - struct_offset) / sizeof(fdt32_t);

    nop_count = 0;

    if (uint32_ld(0) != FDT_BEGIN_NODE) {
      throw std::runtime_error("Root node not found");
    }
    scan(root, 1);
  }

  fdt32_t uint32_ld(const unsigned int index) {
    const fdt32_t r = fdt32_ld(&structs[index]);
    return r;
  }

  /// <summary>
  /// Recursive scan of the nodes.
  /// </summary>
  /// <param name="node"></param>
  /// <param name="index"></param>
  unsigned int scan(Node& node, const unsigned int index)
  {
    node.begin_index = index - 1u;
    unsigned int index_so_far = index;
    node.name = reinterpret_cast<const char*>(&structs[index_so_far]);
    const size_t node_len = strlen(node.name);
    index_so_far += node_len / sizeof(fdt32_t) + 1u;

    fdt32_t token;
    for (;;) {
      token = uint32_ld(index_so_far);
      ++index_so_far;
      switch (token) {
      case FDT_BEGIN_NODE:
        {
          Node child_node;
          const unsigned int next_index = scan(child_node, index_so_far);
          index_so_far = next_index;
          node.nodes.push_back(child_node);
        }
        break;
      case FDT_END_NODE:
        node.end_index = index_so_far;
        return index_so_far;
      case FDT_PROP:
        {
          Property prop;
          prop.begin_index = index_so_far - 1u;
          prop.data_size = uint32_ld(index_so_far);
          ++index_so_far;
          const unsigned int name_offset = uint32_ld(index_so_far);
          ++index_so_far;
          prop.name = &strings[name_offset];
          prop.data = prop.data_size == 0 ? nullptr : reinterpret_cast<uint8_t*>(&structs[index_so_far]);
          index_so_far += (prop.data_size + 3u) / 4u;
          prop.end_index = index_so_far;
          node.properties.push_back(prop);
        }
        break;
      case FDT_NOP:
        ++nop_count;
        break;
      default:
        throw std::runtime_error("Unexpected node!");
      }
    }
    node.end_index = index_so_far;
    return index_so_far;
  }

  Node* find_node(const char* path) {
    if (path[0] == '/') {
      return root.find_node(path + 1);
    }
    else {
      return root.find_node(path);
    }
  }
};

static unsigned int get_buffer_size(const Node& node)
{
  auto prop = node.find_property("trenz.biz,buffer-size");
  if (prop == nullptr) {
    return 0;
  }
  const fdt32_t r = fdt32_ld(reinterpret_cast<const fdt32_t*>(prop->data));
  return r;
}

static bool node_comparator(const Node& lhs, const Node& rhs)
{
  // 1. Are we equal?
  const int name_order = strcmp(lhs.name, rhs.name);
  if (name_order == 0) {
    return false;
  }

  // 2. Get the buffer sizes.
  const int lhs_size = get_buffer_size(lhs);
  const int rhs_size = get_buffer_size(rhs);

  // 3. Compare buffer sizes.
  if (rhs_size == lhs_size) {
    return name_order < 0;
  }
  else if (lhs_size > rhs_size) {
    return true;
  }
  else {
    return false;
  }
}

static void copy_fdt32(fdt32_t* dst, unsigned int& dst_index, const fdt32_t* src, const unsigned int src_begin, const unsigned int src_end)
{
  unsigned int new_dst_index = dst_index;
  for (unsigned int src_index = src_begin; src_index < src_end; ++src_index) {
    dst[new_dst_index] = src[src_index];
    ++new_dst_index;
  }
  dst_index = new_dst_index;
}

static void fix_devicetree_node(const char* filepath, DtbScanner& image_scanner, Node* node_dtb)
{
  const char* FPGA_NODE_PATH = "/amba_pl";

  const Property* prop_dtb = node_dtb->find_property("data");
  if (prop_dtb == nullptr) {
    throw std::runtime_error("Data property not found");
  }

  // 3. Parse device tree
  DtbScanner  dtb_scanner(prop_dtb->data, prop_dtb->data_size);
  printf("%s: Device tree loaded.\n", filepath);
  Node* amba_pl = dtb_scanner.find_node(FPGA_NODE_PATH);
  if (amba_pl == nullptr) {
    throw std::runtime_error("FPGA nodes not found");
  }

  // 4. Parse a copy of the device tree.
  std::vector<uint8_t>  src_dtb(prop_dtb->data, prop_dtb->data + prop_dtb->data_size);
  DtbScanner  src_scanner(&src_dtb[0], src_dtb.size());
  Node* src_amba_pl = src_scanner.find_node(FPGA_NODE_PATH);
  std::vector<Node>& src_nodes = src_amba_pl->nodes;

  printf("%s: Reordering device tree nodes in decreasing order of the buffer size...\n", filepath);
  // 5. Reorder src_amba_pl child nodes.
  std::sort(src_nodes.begin(), src_nodes.end(), node_comparator);

  // 6. Write back to the original device tree.
  unsigned int index_so_far = amba_pl->payload_begin_index();
  const unsigned index_end = amba_pl->payload_end_index();

  // 6a. Write back the properties.
  for (size_t i = 0; i < src_amba_pl->properties.size(); ++i) {
    const Property& prop = src_amba_pl->properties[i];
    copy_fdt32(dtb_scanner.structs, index_so_far, src_scanner.structs, prop.begin_index, prop.end_index);
  }

  // 6b. Write back the nodes.
  for (size_t i = 0; i < src_nodes.size(); ++i) {
    const Node& node = src_nodes[i];
    copy_fdt32(dtb_scanner.structs, index_so_far, src_scanner.structs, node.begin_index, node.end_index);
  }
  // 6c. Padding.
  if (dtb_scanner.nop_count == 0 && index_so_far != index_end) {
    throw std::runtime_error("Internal error #1");
  }
  for (; index_so_far < index_end; ++index_so_far) {
    fdt32_st(&dtb_scanner.structs[index_so_far], FDT_NOP);
  }

  // 7. Rehash
  Node* hash1 = nullptr;
  Property* hash1_value = nullptr;
  Property* hash1_algo = nullptr;
  for (size_t i = 0; i < node_dtb->nodes.size(); ++i) {
    auto& node = node_dtb->nodes[i];
    hash1_value = node.find_property("value");
    hash1_algo = node.find_property("algo");
    if (hash1_value != nullptr && hash1_algo != nullptr) {
      hash1 = &node;
      break;
    }
  }

  if (hash1 == nullptr) {
    throw std::runtime_error("Hash node not found");
  }
  // TODO: check whether the algorithm is still sha-256. Values observed: "sha1", "sha256".
  std::vector<uint8_t>  hash;
  hash_data(hash, prop_dtb->data, prop_dtb->data_size, reinterpret_cast<const char*>(hash1_algo->data));
  memcpy(hash1_value->data, &hash[0], hash.size());

}

static void fix_dtb_for_smartio(const char* filepath)
{
  constexpr const char* PROP_TYPE_FLAT_DT = "flat_dt";

  // 1. Read image.ub.
  std::vector<uint8_t>  bytes = read_all_bytes(filepath);
  if (bytes.size() < sizeof(fdt_header)) {
    throw std::runtime_error("File too small");
  }

  // 2. Parse image.ub
  DtbScanner  image_scanner(&bytes[0], bytes.size());
  printf("%s: loaded.\n", filepath);
  Node* images_node = image_scanner.find_node("/images");
  if (images_node == nullptr) {
    throw std::runtime_error("Node /images not found");
  }
  unsigned int devicetree_count = 0;
  auto& image_nodes = images_node->nodes;
  for (size_t i = 0; i < image_nodes.size(); ++i) {
    Node& node_dtb = image_nodes[i];
    Property* prop_type = node_dtb.find_property("type");
    if (prop_type == nullptr || prop_type->data == nullptr) {
      continue;
    }
    if (strcmp(reinterpret_cast<const char*>(prop_type->data), PROP_TYPE_FLAT_DT) == 0) {
      printf("%s: Patching devicetree node '%s'.\n", filepath, node_dtb.name);
      fix_devicetree_node(filepath, image_scanner, &node_dtb);
      ++devicetree_count;
    }
  }
  printf("%s: Corrected %u device tree nodes.\n", filepath, devicetree_count);

  // 8. Write back
  printf("%s: Writing data back (%u bytes)\n", filepath, (unsigned int)bytes.size());
  write_all_bytes(filepath, &bytes[0], &bytes[0] + bytes.size());
}

int main(int argc, char** argv)
{
  if (argc <= 1) {
    print_usage();
    return 1;
  }

  for (int i = 1; i < argc; ++i) {
    const char* filepath = argv[i];
    printf("%s: Loading...\n", filepath);
    try {
      fix_dtb_for_smartio(filepath);
      printf("%s: SUCCESS\n", filepath);
    }
    catch (const std::exception& ex) {
      printf("%s: FAILURE: %s\n", filepath, ex.what());
    }
  }
}
