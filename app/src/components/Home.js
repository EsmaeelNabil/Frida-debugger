// src/components/Home.js
import React, { useEffect, useState } from 'react';
import { useSocket } from '../context/SocketContext';
import { useNavigate } from 'react-router-dom';

const Home = () => {
    const socket = useSocket();
    const [devices, setDevices] = useState([]);
    const navigate = useNavigate();

    useEffect(() => {
        if (socket) {
            socket.emit('GET_DEVICES');
            socket.on('DEVICES', (data) => {
                setDevices(data);
            });
        }
    }, [socket]);

    const handleDeviceClick = (deviceId) => {
        navigate(`/device/${deviceId}`);
    };

    return (

        <div
            className='flex-row text-center items-center space-x-4 bg-gray-50 rounded-3xl p-4'
        >
            {devices.map((device) => (
                <button
                    className=' bg-green-100 m-8 p-2 rounded-xl'
                    key={device.impl.name}
                    onClick={() => handleDeviceClick(device.impl.id)}
                >
                    <h1 className='font= text-lg'>{device.impl.id}</h1>
                </button>
            )
            )}
        </div>

    );
};

export default Home;
