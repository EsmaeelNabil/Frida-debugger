# Frida-debugger 
```
- Is a Mobile Development/Testing/Debugging/Security tool that gives you superpowers
- Powered by Frida, currently only supporting Android soon IOS.
```

<img width="1371" alt="Screenshot 2024-02-03 at 11 42 17 PM" src="https://github.com/EsmaeelNabil/Frida-debugger/assets/28542963/8188f2f9-1ddf-4c10-b375-f90ca0b69129">


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
- for `backend` 

do `cd Frida-debugger/backend` and run 

```
yarn start
```

###### Docker 
```
  docker build -t frida-debugger .
```
then 
```
  docker run --security-opt seccomp:unconfined -it --privileged -p 3002:3002 frida-debugger
```

- for `front-end` do `cd Frida-debugger/front-end`

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
