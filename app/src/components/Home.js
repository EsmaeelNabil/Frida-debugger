// src/components/Home.js
import React, { useEffect, useState } from 'react';
import { useSocket } from '../context/SocketContext';
import { useNavigate } from 'react-router-dom';
import IconBuffer from './IconBuffer';

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
        <div className="w-auto h-screen bg-gray-100 flex flex-col items-center  p-4">
            <header className="bg-white shadow-lg w-full p-6 flex justify-between items-center rounded-lg mb-8">
                <div className="text-2xl font-bold">Connected Targets</div>
                <nav>
                    <a href="https://github.com/EsmaeelNabil/Frida-debugger" target="_blank" rel="noopener noreferrer">
                        <button className="mr-4 text-blue-600">Docs</button>
                    </a>
                </nav>
            </header>
            <main className="grid grid-cols-2 gap-6 mt-24">
                {devices.map((device, index) => (
                    <button
                        key={device.impl.name}
                        onClick={() => handleDeviceClick(device.impl.id)}
                        className="relative flex items-center justify-center w-96 h-16 bg-gradient-to-r from-blue-50 to-slate-50 text-white font-semibold rounded-full shadow-xl transform transition duration-300 hover:scale-125 mx-8"
                    >
                        <div className="absolute right-0  mr-2 w-12 h-12 bg-gradient-to-r from-slate-50 to-slate-100 text-black shadow-xl rounded-full flex items-center justify-center">
                            {/* <IconBuffer icon={device.impl.icon.image}></IconBuffer> */}
                            {
                                <div className="text-xl">{device.impl.type === "usb" ? "📱" : "💻"}</div>

                            }
                        </div>
                        <div className="text-center text-blue-950">{device.impl.name}</div>
                    </button>
                ))}
            </main>
        </div>

    );
};

export default Home;
