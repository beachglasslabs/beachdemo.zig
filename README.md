Rewrote the front-end demo in ZAX (Zig/Zap Alpinejs htmX :stuck_out_tongue_winking_eye:)

This is the rewrite of an earlier [rewrite](https://github.com/beachglasslabs/beachdemo.jl) written in [Juila](https://julia.org):
 * The original UI is based on a great video tutorial I found on [Youtube](https://github.com/AntonioErdeljac/next-netflix-tutorial) and you can find my own [nextjs](https://nextjs.org) version [here](https://github.com/edyu/netflix-clone).
 * I rewrote the UI to be based on [HTMX](https://htmx.org) and [Alpinejs](https://alpinejs.dev) instead of the original [next.jls](https://nextjs.org).
 * The backend is completely rewritten in [zig](https://ziglang.org).
 * Sepcial thanks to [Rene](https://github.com/renerocksai) for [zap](https://github.com/zigzap/zap) and all the help along the way.
 * The users and sessions are ephemeral to remove the dependency on Mongodb Atlas in the [original](https://github.com/edyu/netflix-clone) version.

To test it out (It doesn't work yet!):
 1. `git clone git@github.com:beachglasslabs/beachtube.git`
 2. `npm install` to install npm packages
 3. `cp env.oauth.sample.json env.oauth.json` and then optionally fill out the oauth2 information from [github](https://docs.github.com/en/apps/oauth-apps/building-oauth-apps/authorizing-oauth-apps) and [google](https://developers.google.com/identity/protocols/oauth2).
 4. `npm run dev` to start the server
 5. go to [http://localhost:3000](http://localhost:3000) on your browser.
