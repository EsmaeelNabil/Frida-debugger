# Frida-debugger 
```
- Is a Mobile Development/Testing/Debugging/Security tool that gives you superpowers
- Powered by Frida, currently only supporting Android soon IOS.
```

##### prerequisite

- `node`
- `yarn`
- Android Development Environment
  - `gradle`
  - `jdk`
  - `ADB`

##### installation

```
git clone https://github.com/EsmaeelNabil/Frida-debugger.git
cd Frida-debugger/backend
yarn install
```

##### running in dev mode
- for `backend` do `cd Frida-debugger/backend` and run 

```
yarn start
```

- for `desktop app/front-end` do `cd Frida-debugger/front-end`

```
./gradlew run
```


---

##### How to use
- `runEmulator.sh` to launch an emulator
  - `Android SDK` is required
- `prepareFridaEmulator.sh` to ship `frida server` to the emulator.
  - Has to be done everytime if it's not saved in the emulator in case of restarts.
  - You need to run it again if you couldn't see a `pid` with a message like this `Frida server is running on  with pid 21420.`
  - `ADB` is required

in case you need an updated `Frida-Server` use `tools/fmc` to download it.
```
but it has to be renamed to fridaserver for ./prepareFridaEmulator.sh to work properly.
```

![1.png](art%2F1.png)
![2.png](art%2F2.png)
![3.png](art%2F3.png)