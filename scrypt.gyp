{
  "targets": [{
    "target_name": "scrypt",
    "type": "<(library)",
    "include_dirs": [
      ".",
      "include",
    ],
    "direct_dependent_settings": {
      "include_dirs": [
        "include"
      ],
    },
    "sources": [
      "src/hmac.c",
      "src/salsa20.c",
      "src/scrypt.c",
      "src/sha256.c",
      "src/pbkdf2.c",
    ],

    "conditions": [
      ["library == 'static_library'", {
        "standalone_static_library": 1,
      }],
      ["library == 'shared_library' and GENERATOR == 'xcode'", {
        "mac_bundle": 1,
        "mac_framework_headers": [
          "include/ispdy.h",
        ],
      }]
    ],
  }, {
    "target_name": "test",
    "type": "executable",

    "dependencies": [
      "scrypt",
    ],

    "include_dirs": [
      "."
    ],

    "sources": [
      "test/test.c",

      "test/hmac.c",
      "test/salsa20.c",
      "test/sha256.c",
      "test/scrypt.c",
      "test/pbkdf2.c",
    ],
  }]
}
