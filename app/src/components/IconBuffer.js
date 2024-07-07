import React, { useEffect, useState } from 'react';

const IconBuffer = ({ icon }) => {
  const [iconSrc, setIconSrc] = useState('');

  useEffect(() => {
    if (icon && icon.image) {
      const base64String = arrayBufferToBase64(icon.image);
      setIconSrc(`data:image/png;base64,${base64String}`);
    }
  }, [icon]);

  return (
    <div>
      {iconSrc ? (
        <img src={iconSrc} alt="Icon" />
      ) : (
        <p>Loading...</p>
      )}
    </div>
  );
};

// Utility function
function arrayBufferToBase64(buffer) {
  let binary = '';
  const bytes = new Uint8Array(buffer);
  const len = bytes.byteLength;
  for (let i = 0; i < len; i++) {
    binary += String.fromCharCode(bytes[i]);
  }
  return window.btoa(binary);
}

export default IconBuffer;
