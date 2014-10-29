# secure-loader

This is an old project which got dug up, so I open-sourced it.

This project contains two parts: `Loader` and `Loadee`. `Loader` is an executable when built, which
resembles a specialised process injector and `Loadee` is a special `.dll` file which can only be
injected by `Loader` and not other injectors (after i.e. authentication, or such).

License is MIT. Terms can be found in `LICENSE`.
