%{
  configs: [
    %{
      name: "default",
      files: %{
        included: [
          "lib/",
          "src/",
          "test/",
          "web/",
          "apps/*/lib/",
          "apps/*/src/",
          "apps/*/test/",
          "apps/*/web/"
        ],
        excluded: [
          ~r"/_build/",
          ~r"/deps/",
          ~r"/node_modules/",
          # Exclude the problematic test file that Credo can't parse
          "test/base_acl_ex/identity/core/entities/permission_test.exs"
        ]
      },
      strict: false,
      color: true
    }
  ]
}
