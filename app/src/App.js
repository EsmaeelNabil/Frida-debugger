// src/App.js
import React from 'react';
import { BrowserRouter as Router, Route, Routes } from 'react-router-dom';
import { SocketProvider } from './context/SocketContext';
import Home from './components/Home';
import DeviceDetails from './components/DeviceDetails';
import AppDetails from './components/AppDetails';
import Connected from './components/Connected';

function App() {
  return (
    <SocketProvider>
      <Router>
        <Routes>
          <Route path="/" element={<Home />} />
          <Route path="/device/:deviceId" element={<DeviceDetails />} />
          <Route path="/app/:deviceId/:appName" element={<AppDetails />} />
          <Route path="/connected/:appId" element={<Connected />} />
        </Routes>
      </Router>
    </SocketProvider>
  );
}

export default App;