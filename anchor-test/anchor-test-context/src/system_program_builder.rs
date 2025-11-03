use litesvm::LiteSVM;

pub struct SystemProgramBuilder<'a> {
    pub(crate) svm: &'a mut LiteSVM,
}

impl<'a> SystemProgramBuilder<'a> {
    // TODO: Implement system program methods like:
    // - transfer()
    // - create_account()
    // - allocate()
    // etc.
}
