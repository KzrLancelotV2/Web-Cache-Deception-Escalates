# Member 4 Report: Live Exploit Simulation & Impact Analysis

## 1. What My Role Was (Member 4)
While the rest of the team focused on setting up the core app infrastructure (Member 1) and writing the engine to automatically discover the vulnerability (Members 2 and 3), my job was to handle the **real-world impact side of things**. 

Basically, I had to prove why this Web Cache Deception bug actually matters. To do that, I built a mock attacker landing page (`demo_server.py`) that shows how an outsider can trick a user, poison the Nginx cache, and easily steal an active user's **Anti-CSRF Token** to set up a serious account takeover.

---

## 2. How My Code Connects to the Team's Pipeline

Instead of using a hardcoded link, my script connects directly to what Member 2's detection engine uncovers. Here is the layout of how the data flows during our demo:

   [Member 2/3 Engine] ---> Writes vulnerable path to findings.json ---> [My Demo Server (Port 9090)]
                                                                                  │
   [Attacker Window] <--- Sees Victim's Private Stolen Token <────────────────────┤ (Victim clicks button)

* **The Hand-off:** Member 2's script audits the server, finds a working path confusion layout (like a profile path ending in `.css`), and writes it into `findings.json`.
* **Dynamic Sourcing:** My script acts as a helper application running on an independent port (`9090`). It automatically parses that shared JSON file to pull out the live attack link.
* **The Redirection Trap:** My script hosts a clean, friendly-looking university update webpage. When the victim interacts with it and clicks the action button, my backend code catches the click and routes them directly onto the vulnerable path, springing the cache exploit on the target proxy server.

---

## 3. How the Attack Plays Out (Step-by-Step)

Here is exactly what happens during the live exploit when we run through it in class using two side-by-side browser windows:

### Phase 1: Setting up the Trap
We spin up the containers and run Member 2's script to map out the vulnerable routes, which feeds my server the live path. We have a logged-in window for the Victim and an Incognito window for the Attacker.

### Phase 2: Poisoning the Cache
The logged-in Victim visits our fake portal on port `9090` and clicks the button. 
* Their browser gets redirected to the real app server using the hybrid path (like `/profile/style.css`).
* **The Backend:** Flask politely ignores the trailing `.css` extension and loads the victim's real profile data along with a fresh **Anti-CSRF Token**.
* **The Proxy:** Nginx spots the `.css` extension, assumes it's just a public layout graphic, completely ignores the server's privacy headers, and shoves a full copy of the victim's personalized HTML page straight into its cache memory (returning a cache `MISS`).

### Phase 3: Stealing the Keys
Now, our Attacker takes that exact same `.css` link and throws it into their completely logged-out Incognito window.
* **The Result:** Instead of hitting the backend database or asking for a password, Nginx instantly pulls up the saved page right out of its cache box and hands it to the attacker (returning a cache `HIT`).
* **The Damage:** The attacker is now staring at a perfect layout of the victim's profile page, completely uncovering their private **Anti-CSRF token**. The attacker can now copy this token to execute a password change out-of-band.

---

## 4. Defense Verification: Fixing the Bug
To wrap up my deliverable, I verified how our defensive steps break this attack loop. 

Once we modify the `nginx.conf` file to stop ignoring backend privacy headers (removing `proxy_ignore_headers`) or force Nginx to check if a static file actually exists on the hard drive before caching it, the attack fails completely. Retrying Phase 3 shows that Nginx will correctly drop the cache request or return a clean 404 error, keeping the victim's token totally safe from the attacker.