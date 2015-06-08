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
      "src/chacha.c",
      "src/pbkdf2.c",
    ],
    "conditions": [
      # Platform-specifics
      ["OS == 'mac'", {
        "sources": [
          "src/backend/osx.c",
        ],
      }],
    ],
  }, {
    "target_name": "test",
    "type": "executable",

    "dependencies": [
      "scrypt",
    ],

    "sources": [
      "test/main.c",

      "test/chacha.c",
      "test/pbkdf2.c",
    ],
  }]
}
