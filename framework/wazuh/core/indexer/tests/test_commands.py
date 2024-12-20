from dataclasses import asdict
from unittest import mock

import pytest
from opensearchpy import exceptions
from wazuh.core.exception import WazuhError
from wazuh.core.indexer.base import POST_METHOD, IndexerKey
from wazuh.core.indexer.commands import (
    COMMAND_USER_NAME,
    CommandsManager,
    create_restart_command,
    create_set_group_command,
    create_update_group_command,
)
from wazuh.core.indexer.models.commands import (
    Action,
    Command,
    CreateCommandResponse,
    ResponseResult,
    Source,
    Target,
    TargetType,
)
from wazuh.core.indexer.utils import convert_enums


class TestCommandsManager:
    index_class = CommandsManager
    create_command = Command(source=Source.ENGINE)

    @pytest.fixture
    def client_mock(self) -> mock.AsyncMock:
        return mock.AsyncMock()

    @pytest.fixture
    def index_instance(self, client_mock) -> CommandsManager:
        return self.index_class(client=client_mock)

    async def test_create(self, index_instance: CommandsManager, client_mock: mock.AsyncMock):
        """Check the correct functionality of the `create` method."""
        return_value = {
            IndexerKey._INDEX: CommandsManager.INDEX,
            IndexerKey._DOCUMENTS: [
                {IndexerKey._ID: 'pBjePGfvgm'},
                {IndexerKey._ID: 'mp2Xymz6F3'},
                {IndexerKey._ID: 'aYsJYUEmVk'},
                {IndexerKey._ID: 'QTjrFfpoIS'},
            ],
            IndexerKey.RESULT: ResponseResult.CREATED,
        }
        client_mock.transport.perform_request.return_value = return_value

        response = await index_instance.create([self.create_command])

        assert isinstance(response, CreateCommandResponse)
        client_mock.transport.perform_request.assert_called_once_with(
            method=POST_METHOD,
            url=f'{index_instance.PLUGIN_URL}/commands',
            body={
                'commands': [
                    asdict(self.create_command, dict_factory=convert_enums),
                ]
            },
        )

        document_ids = [document.get(IndexerKey._ID) for document in return_value.get(IndexerKey._DOCUMENTS)]
        assert response.index == return_value.get(IndexerKey._INDEX)
        assert response.document_ids == document_ids
        assert response.result == return_value.get(IndexerKey.RESULT)

    @pytest.mark.parametrize('exc', [exceptions.RequestError, exceptions.TransportError])
    async def test_create_ko(self, index_instance: CommandsManager, client_mock: mock.AsyncMock, exc):
        """Check the error handling of the `create` method."""
        client_mock.transport.perform_request.side_effect = exc(400, 'error')
        with pytest.raises(WazuhError, match='.*1761.*'):
            await index_instance.create([self.create_command])


def test_create_restart_command():
    """Check the correct functionality of the `create_restart_command` function."""
    agent_id = '0191dd54-bd16-7025-80e6-ae49bc101c7a'
    expected_command = Command(
        source=Source.SERVICES,
        target=Target(
            type=TargetType.AGENT,
            id=agent_id,
        ),
        action=Action(name='restart', version='5.0.0'),
        user=COMMAND_USER_NAME,
        timeout=100,
    )

    command = create_restart_command(agent_id=agent_id)

    assert command == expected_command
    assert command.document_id is None


def test_create_set_group_command():
    """Check the correct functionality of the `create_set_group_command` function."""
    agent_id = '0191dd54-bd16-7025-80e6-ae49bc101c7a'
    groups = ['default', 'group1', 'group3']
    expected_command = Command(
        source=Source.SERVICES,
        target=Target(
            type=TargetType.AGENT,
            id=agent_id,
        ),
        action=Action(name='set-group', args=groups, version='5.0.0'),
        user=COMMAND_USER_NAME,
        timeout=100,
    )

    command = create_set_group_command(agent_id=agent_id, groups=groups)

    assert command == expected_command
    assert command.document_id is None


def test_create_update_group_command():
    """Check the correct functionality of the `create_update_group_command` function."""
    agent_id = '0191dd54-bd16-7025-80e6-ae49bc101c7a'
    expected_command = Command(
        source=Source.SERVICES,
        target=Target(
            type=TargetType.AGENT,
            id=agent_id,
        ),
        action=Action(name='update-group', version='5.0.0'),
        user=COMMAND_USER_NAME,
        timeout=100,
    )

    command = create_update_group_command(agent_id=agent_id)

    assert command == expected_command
    assert command.document_id is None
