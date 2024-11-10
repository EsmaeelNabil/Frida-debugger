import IconBuffer from '../IconBuffer.js';

function AppDetails({ details }) {
  return (
    <>
      <div className='m-8 flex items-center space-x-2 justify-between'>
        <div className='flex items-center space-x-2'>
          <div className="size-11">
            <IconBuffer icon={details.parameters.icons[0]} />
          </div>
          <span className={`font-mono rounded-md p-2 text-black ${details.pid === 0 ? 'bg-red-200' : 'bg-green-100'}`}>{details.name}</span>
        </div>
      </div>

      <div className="flex flex-col text-sm text-gray-700 m-8">
        <span>{details.identifier} : {details.pid}</span>
        <span>PID:{details.pid} - PPID {details.parameters.ppid}</span>
        <span>Build : {details.parameters.build}</span>
        <span>dataDir : {details.parameters.dataDir}</span>
        <span>pid : {details.parameters.pid}</span>
        <span>ppid : {details.parameters.ppid}</span>
        <span>started : {details.parameters.started}</span>
        <span>targetSdk : {details.parameters.targetSdk}</span>
        <span>user : {details.parameters.user}</span>
        <span>version : {details.parameters.version}</span>
      </div>

    </>
  );
}

export default AppDetails;
