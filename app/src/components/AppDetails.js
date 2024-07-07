import React, { useEffect, useMemo, useState } from 'react';
import { useSocket } from '../context/SocketContext';
import { useParams } from 'react-router-dom';
import IconBuffer from './IconBuffer';
import { FilePicker } from 'evergreen-ui';
import Editor from 'react-simple-code-editor';
import { highlight, languages } from 'prismjs/components/prism-core';
import 'prismjs/components/prism-clike';
import 'prismjs/components/prism-javascript';
import 'prismjs/themes/prism.css';

const AppDetails = () => {
  let fileReader;
  const socket = useSocket();
  const { deviceId, appName } = useParams();

  // Messages
  const [messages, setMessages] = useState([]);
  const addMessage = (data) => {
    setMessages((prevMessages) => [...prevMessages, data]);
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
        <div className='flex space-x-2'>
          {
            appDetails.pid !== 0 ?
              <button className='rounded-md bg-green-500 text-white font-mono shadow-md p-2' onClick={attachToApp}>Attach</button>
              : <></>
          }

          <button className='rounded-md bg-yellow-300  text-black font-mono shadow-md p-2 hover:animate-pulse' onClick={launchApp}>Launch App</button>
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

      <FilePicker className='m-10' accept={".js"} width={400} onChange={(files) => setFiles(files)} placeholder="Select the file here!" />


      <Editor
        className='m-8 shadow-sm border-spacing-3 border-slate-100 border-2 drop-shadow-sm p-20'
        value={code}
        onValueChange={code => setCode(code)}
        highlight={code => highlight(code, languages.js)}
        padding={10}
        style={{
          fontFamily: '"Fira code", "Fira Mono", monospace',
          fontSize: 14,
        }}
      />

      {
        messages.length === 0 ? <></> : <span className='text-xl font-bold m-8'>Messages</span>
      }



      <div className='m-8 h-96 overflow-y-auto shadow-xl'>
        {
          messages.map((message, index) =>
          (
            <div key={index} className=''>
              <span className='text-sm text-gray-400'>[MESSAGE]</span>
              <span className='text-gray-900'> {message}</span>
            </div>
          )
          )
        }

      </div>



    </div >
  );
};

export default AppDetails;
