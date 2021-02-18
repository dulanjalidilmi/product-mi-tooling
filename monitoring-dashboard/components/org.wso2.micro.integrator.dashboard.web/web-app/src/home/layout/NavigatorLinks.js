import ProxyIcon from '@material-ui/icons/Notes';
import EndpointIcon from '@material-ui/icons/Send';
import InbountEpIcon from '@material-ui/icons/Transform';
import MessageProcessorIcon from '@material-ui/icons/Message';
import MessageStoreIcon from '@material-ui/icons/StoreMallDirectory';
import ApiIcon from '@material-ui/icons/Apps';
import Event from '@material-ui/icons/Event';
import TemplateIcon from '@material-ui/icons/WrapText';
import SequenceIcon from '@material-ui/icons/CompareArrows';
import LocalEntriesIcon from '@material-ui/icons/Assignment';
import ConnectorIcon from '@material-ui/icons/CastConnected';
import CappIcon from '@material-ui/icons/Dashboard';
import UserIcon from '@material-ui/icons/People';
import LogFileIcon from '@material-ui/icons/Description';
import LayersIcon from '@material-ui/icons/Layers';

export const categories = [
    {
      id: 'General',
      children: [
        { id: 'Proxy Services', to: '/proxy-services', icon: <ProxyIcon /> },
        { id: 'Endpoints', to: '/endpoints', icon: <EndpointIcon /> },
        { id: 'Inbound Endpoints', to: '/inbound-endpoints', icon: <InbountEpIcon /> },
        { id: 'Message Processors', to: '/message-processors', icon: <MessageProcessorIcon /> },
        { id: 'Message Stores', to: '/message-stores', icon: <MessageStoreIcon /> },
        { id: 'API', to: '/apis', icon: <ApiIcon /> },
        { id: 'Templates', to: '/templates', icon: <TemplateIcon /> },
        { id: 'Sequences', to: '/sequences', icon: <SequenceIcon /> },
        { id: 'Tasks', to: '/tasks', icon: <Event /> },
        { id: 'Local Entries', to: '/local-entries', icon: <LocalEntriesIcon /> },
        { id: 'Data Services', to: '/data-services', icon: <LayersIcon /> },
        { id: 'Connectors', to: '/connectors', icon: <ConnectorIcon /> },
        { id: 'Carbon Applications', to: '/carbon-applications', icon: <CappIcon /> },
        { id: 'Log Files', to: '/log-files', icon: <LogFileIcon /> },
      ],
    },
    {
      id: 'Global Settings',
      children: [
        { id: 'Log Configs', to: '/log-configs', icon: <LocalEntriesIcon /> },
        { id: 'Users', to: '/users', icon: <UserIcon /> },
      ],
    },
  ];

  export const getIdFromRoute = (route) => {
      let allChildren = [];
      categories.map((cat) => {
          allChildren = [...allChildren, ...cat.children];
      })
      const selected = allChildren.find(child => child.to === route);
      return selected ? selected : allChildren[0] ;
  }
