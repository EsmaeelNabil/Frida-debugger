// src/components/Connected.js
import React from 'react';
import { useParams } from 'react-router-dom';

const Connected = () => {
  const { appId } = useParams();

  return (
    <div>
      <h1>Connected to App {appId}</h1>
      {/* Display connected app's interface here */}
    </div>
  );
};

export default Connected;
