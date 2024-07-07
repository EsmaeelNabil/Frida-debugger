import React, { useEffect, useMemo, useState } from 'react';
import { useSocket } from '../context/SocketContext';
import { useParams } from 'react-router-dom';
import IconBuffer from './IconBuffer';
import { CollapseAllIcon, FilePicker, Table } from 'evergreen-ui';
import Editor from 'react-simple-code-editor';
import { highlight, languages } from 'prismjs/components/prism-core';
import 'prismjs/components/prism-clike';
import 'prismjs/components/prism-javascript';
import 'prismjs/themes/prism.css';

import { LogViewer, LogViewerSearch } from "@patternfly/react-log-viewer";
import { Toolbar, ToolbarContent, ToolbarItem } from "@patternfly/react-core";

const AppDetails = () => {
  let fileReader;
  const socket = useSocket();
  const { deviceId, appName } = useParams();

  // Messages
  const [messages, setMessages] = useState([]);
  const addMessage = (data) => {
    console.log(data.toString());
    setMessages((prevMessages) => [...prevMessages, data.toString()]);
  };

  const clearMessages = () => {
    setMessages([]);
  };

  // Script content
  const initialScript = `send('Hello from ${appName}!');`;
  const [files, setFiles] = useState(null);
  const [code, setCode] = useState(initialScript);
  // updates the code when the file changes
  useMemo(() => {
    if (files) {
      // eslint-disable-next-line react-hooks/exhaustive-deps
      fileReader = new FileReader();
      fileReader.onloadend = (e) => {
        setCode(fileReader.result);
      };
      fileReader.readAsText(files[0]);
    } else {
      setCode(initialScript);
    }
  }, [files]);

  // App details
  const [appDetails, setAppDetails] = useState(null);
  const appIdentifier = useMemo(() => appDetails ? appDetails.identifier : "", [appDetails]);

  useEffect(() => {
    if (socket) {
      socket.emit('GET_APP', { deviceId, appName });
      socket.on('APP', (data) => {
        setAppDetails(data);
      });

      socket.on('ON_MESSAGE', (data) => {
        addMessage(data);
      });
    }
  }, [socket, deviceId, appName]);



  const attachToApp = () => {
    socket.emit('ATTACH_TO_APP', { deviceId: deviceId, appName: appName, script: code });
  };

  const launchApp = () => {
    socket.emit('LAUNCH_APP', { deviceId: deviceId, appIdentifier: appIdentifier, script: code });
  };

  const unloadScripts = () => {
    socket.emit('UNLOAD_SCRIPTS');
  }

  if (!appDetails) {
    return <p>Loading...</p>;
  }


  return (
    <div>
      <div className='m-8 flex items-center space-x-2 justify-between'>
        <div className='flex items-center space-x-2'>
          <div className="size-11">
            <IconBuffer icon={appDetails.parameters.icons[0]} />
          </div>
          <span className={`font-mono rounded-md p-2 text-black ${appDetails.pid === 0 ? 'bg-red-200' : 'bg-green-100'}`}>{appDetails.name}</span>
        </div>
      </div>



      <div className="flex flex-col text-sm text-gray-700 m-8">
        <span>{appDetails.identifier} : {appDetails.pid}</span>
        <span>PID:{appDetails.pid} - PPID {appDetails.parameters.ppid}</span>
        <span>Build : {appDetails.parameters.build}</span>
        <span>dataDir : {appDetails.parameters.dataDir}</span>
        <span>pid : {appDetails.parameters.pid}</span>
        <span>ppid : {appDetails.parameters.ppid}</span>
        <span>started : {appDetails.parameters.started}</span>
        <span>targetSdk : {appDetails.parameters.targetSdk}</span>
        <span>user : {appDetails.parameters.user}</span>
        <span>version : {appDetails.parameters.version}</span>
      </div>

      <div className='flex flex-wrap text-center items-center justify-stretch'>
        <FilePicker className='m-10' accept={".js"} width={400} onChange={(files) => setFiles(files)} placeholder="Select the file here!" />
        <div className='flex space-x-2'>
          {
            appDetails.pid !== 0 ?
              <button className='rounded-md bg-green-500 text-white font-mono shadow-md p-2' onClick={attachToApp}>Attach</button>
              : <></>
          }

          <button className='rounded-md bg-yellow-300  text-black font-mono shadow-md p-2 hover:animate-pulse' onClick={launchApp}>Launch App</button>
          <button className='rounded-md bg-red-300  text-black font-mono shadow-md p-2 hover:animate-pulse' onClick={unloadScripts}>Unload Scripts</button>
          <button className='rounded-md bg-red-300  text-black font-mono shadow-md p-2 hover:animate-pulse' onClick={clearMessages}>Clear Messages</button>

        </div>
      </div>



      <Editor
        className='m-8 shadow-sm border-spacing-3 border-slate-100 border-2 drop-shadow-sm p-20'
        value={code}
        onValueChange={code => setCode(code)}
        highlight={code => highlight(code, languages.js)}
        padding={10}
        style={{
          fontFamily: '"Fira code", "Fira Mono", monospace',
          fontSize: 12,
        }}
      />

      {
        messages.length === 0 ? <></> : <span className='text-xl font-bold m-8'>Messages</span>
      }

      {/* highlight(code, languages.javascript) */}

      
      <div className='m-8'>
        <LogViewer
          hasLineNumbers={true}
          height={500}
          data={messages}
          theme="light"
          isTextWrapped={true}
        />

      </div>

    </div >
  );
};

export default AppDetails;
