// src/components/DeviceDetails.js
import React, { useEffect, useState } from 'react';
import { useSocket } from '../context/SocketContext';
import { useParams, useNavigate } from 'react-router-dom';
import IconBuffer from './IconBuffer';

const DeviceDetails = () => {
  const { deviceId } = useParams();
  const socket = useSocket();
  const [apps, setApps] = useState([]);
  const navigate = useNavigate();

  useEffect(() => {
    if (socket) {
      socket.emit('GET_ALL_APPS', deviceId);
      socket.on('ALL_APPS', (data) => {
        setApps(data);
      });
    }
  }, [socket, deviceId]);

  const handleAppClick = (appName) => {
    navigate(`/app/${deviceId}/${appName}`);
  };

  return (
    <div>

      <h1 className='text-xl font-thin m-8'>Apps on Device {deviceId}</h1>

      <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 gap-6 m-4">
      {apps.map((app) => (
        <div
          className={`flex items-center space-x-4 ${app.pid === 0 ? 'bg-slate-100' : 'bg-green-100'} rounded-3xl p-4`}
          key={app.identifier}
          onClick={() => handleAppClick(app.name)}
        >
          <div className="size-7">
            <IconBuffer icon={app.parameters.icons[0]} />
          </div>

          <div className="flex flex-col">
            <span className="text-xl font-semibold">{app.name}</span>
            <span className="text-sm text-gray-500">{app.identifier} : {app.pid}</span>
          </div>

        </div>
      ))}
    </div>
    </div >
  );
};

export default DeviceDetails;
