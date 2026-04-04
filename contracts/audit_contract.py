from pyteal import *


def approval_program():
    store_batch = Seq(
        [
            Assert(Txn.application_args.length() == Int(2)),
            App.globalPut(Bytes("last_root"), Txn.application_args[1]),
            App.globalPut(
                Bytes("batch_count"),
                App.globalGet(Bytes("batch_count")) + Int(1),
            ),
            Approve(),
        ]
    )

    on_create = Seq(
        [
            App.globalPut(Bytes("batch_count"), Int(0)),
            App.globalPut(Bytes("last_root"), Bytes("")),
            Approve(),
        ]
    )

    program = Cond(
        [Txn.application_id() == Int(0), on_create],
        [
            Txn.on_completion() == OnComplete.NoOp,
            Cond(
                [Txn.application_args[0] == Bytes("store_batch"), store_batch],
            ),
        ],
    )
    return program


def clear_program():
    return Approve()


def write_teal_files():
    with open("approval.teal", "w", encoding="utf-8") as approval_file:
        approval_file.write(
            compileTeal(approval_program(), mode=Mode.Application, version=6)
        )

    with open("clear.teal", "w", encoding="utf-8") as clear_file:
        clear_file.write(
            compileTeal(clear_program(), mode=Mode.Application, version=6)
        )


if __name__ == "__main__":
    write_teal_files()
