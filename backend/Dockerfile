# Use the latest Node.js image
FROM node:20-bullseye

RUN apt-get update && apt-get install -y android-tools-adb
ENV ANDROID_ADB_SERVER_ADDRESS="host.docker.internal" 

# Set the working directory inside the container
WORKDIR /usr/src/app

# Copy package.json and yarn.lock to the working directory
COPY package*.json ./

# Install dependencies using Yarn
RUN npm install
# Install ts-node as a dev dependency
RUN npm install --save-dev ts-node
# Copy the rest of the application code to the working directory
COPY . .

# Expose the port on which the WebSocket server will listen
EXPOSE 3002

# Start the WebSocket server using ts-node
CMD ["npm", "start"]
