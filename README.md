Rewrite the front-end demo in ZAX (Zig/Zap Alpinejs htmX :stuck_out_tongue_winking_eye:)

This is the rewrite of an earlier [rewrite](https://github.com/beachglasslabs/jax-demo) in [Juila](https://julia.org):
 * The original UI is based on a great video tutorial I found on [Youtube](https://github.com/AntonioErdeljac/next-netflix-tutorial).
 * I rewrote the UI to be based on [HTMX](https://htmx.org) and [Alpinejs](https://alpinejs.dev).
 * The backend is going to be completely rewritten in [zig](https://ziglang.org).
 * Sepcial thanks to Rene for [zap](https://github.com/zigzap/zap)
 * I'm plannning to replace the Mongodb Atlas dependency by using an embedded database.

To test it out (It doesn't work yet!):
 1. `git clone git@github.com:beachglasslabs/beachtube.git`
 2. `npm install` to install npm packages
 4. `npm run dev` to start the server
