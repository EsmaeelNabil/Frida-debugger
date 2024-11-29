import React from 'react';
import { BrowserRouter as Router, Route, Routes } from 'react-router-dom';
import { SocketProvider } from './context/SocketContext';
import Home from './components/Home.jsx';
import DeviceDetails from './components/DeviceDetails.jsx';
import AppDashboard from './components/AppDashboard/AppDashboard.jsx';
import Connected from './components/Connected.jsx';

function App() {
    return (
        <SocketProvider>
            <Router>
                <Routes>
                    <Route path="/" element={<Home />} />
                    <Route path="/device/:deviceId" element={<DeviceDetails />} />
                    <Route path="/app/:deviceId/:appName" element={<AppDashboard />} />
                    <Route path="/connected/:appId" element={<Connected />} />
                </Routes>
            </Router>
        </SocketProvider>
    );
}

export default App;